# VIGIA — Google Cloud deployment

Step-by-step spin-up for the live purple-team backend on Google Cloud Run.
This is the deployed backend the demo video shows running on Google Cloud.

## What runs where

- **Cloud Run** (`vigia-live`, region `us-central1`) hosts the FastAPI backend
  (`service/app.py`): the deterministic forensic core + the ADK agent behind
  an HTTP API.
- **Vertex AI** serves Gemini 3.5 Flash to the ADK agent, through the Cloud
  Run service identity — no API key stored in the service.
- The verdict is sealed by the deterministic core, never by Gemini. Swapping
  the model changes only the narration.

Three mandatory hackathon boxes, all checked: Gemini 3.5+ (Vertex AI), a
Google Agent Framework (ADK), and a Google Cloud service (Cloud Run).

## Prerequisites

- A Google Cloud project with billing (`vigia-497422`).
- Enabled APIs: `run`, `aiplatform`, `cloudbuild`, `artifactregistry`,
  `firestore`, and — for the autonomous sweep — `pubsub` and
  `cloudscheduler`.
  ```bash
  gcloud services enable run.googleapis.com aiplatform.googleapis.com \
      cloudbuild.googleapis.com artifactregistry.googleapis.com \
      firestore.googleapis.com pubsub.googleapis.com \
      cloudscheduler.googleapis.com --project vigia-497422
  ```
- A Firestore database, because that is where a case's mission memory and its
  two hash chains live between cycles. Without one the service still starts —
  it degrades to memory and logs that it did — but nothing survives a restart,
  which is exactly the claim the fleet rests on.
  ```bash
  gcloud firestore databases create --location nam5 --project vigia-497422
  ```

## Deploy

```bash
gcloud run deploy vigia-live \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 1Gi --cpu 1 --timeout 300 \
  --set-env-vars GOOGLE_CLOUD_PROJECT=vigia-497422,\
GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_LOCATION=global \
  --project vigia-497422
```

### Gotcha: `GOOGLE_CLOUD_PROJECT` is not set for you

Cloud Run injects `PORT`, `K_SERVICE` and friends, but **not**
`GOOGLE_CLOUD_PROJECT`. The case store reads it to reach Firestore, and when it
is absent the store degrades to memory rather than guessing — honestly, with a
warning in the log, but a service that looks healthy. The symptom on camera is
`/health` reporting `"case_store": "memory"`, mission memory that resets on
every cold start, and a fleet that cannot claim continuity across weeks.
Set it explicitly, as above, and confirm on `/health` before recording.

### Gotcha: Vertex location for Gemini 3.x is `global`, not a region

Gemini 3.x publisher models are served on Vertex AI's **`global`** endpoint,
not regional ones. `GOOGLE_CLOUD_LOCATION=us-central1` yields a 404
(`Publisher model ... was not found`). Set `GOOGLE_CLOUD_LOCATION=global`
(the Cloud Run service itself still lives in `us-central1`). To change it on
an existing service without a rebuild:
```bash
gcloud run services update vigia-live --region us-central1 \
  --update-env-vars GOOGLE_CLOUD_LOCATION=global --project vigia-497422
```

## Endpoints

Live URL: `https://vigia-live-1028999311218.us-central1.run.app`

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | liveness + model/build info |
| GET | `/hunts` | the curated VQL hunts available |
| POST | `/investigate` | run an investigation (mode `scripted` or `agent`) |
| GET | `/investigations/{id}` | fetch a stored investigation |
| GET | `/investigations/{id}/stream` | sealed verdict entries (chain re-verified on read) |

Scripted (no LLM, deterministic — the replay/dashboard path):
```bash
curl -s -X POST "$URL/investigate" -H 'Content-Type: application/json' \
  -d '{"case_id":"DEMO-001","examiner_id":"purple-op-01","mode":"scripted"}'
```

Agent (Gemini drives the hunt and narrates the sealed verdict):
```bash
curl -s -X POST "$URL/investigate" -H 'Content-Type: application/json' \
  -d '{"case_id":"DEMO-001","examiner_id":"purple-op-01","mode":"agent",
       "prompt":"Run a baseline sweep, adjudicate it, give the sealed verdict."}'
```

## Autonomous operation (runs without a human, and decides while it runs)

Cloud Scheduler publishes to a Pub/Sub topic on a cron; a push subscription
delivers to `/tasks/sweep`, which wakes the fleet. Every case that is *due* gets
one autonomous cycle: the commander reads the case's mission memory, tasks the
specialists it is cleared to task, adjudicates through the deterministic engine,
and sets its own next wake-up.

The cron is only the wake-up — the cadence is per case, decided by the fleet, so
a 15-minute schedule does not mean a 15-minute collection interval on every
host. One wake-up runs at most `VIGIA_SWEEP_MAX_CYCLES` cycles (default 10),
worst sealed verdict first, deferring the rest to the next one; raise it if your
fleet is larger than your cron is frequent. `/health` reports `autonomous_sweeps`, `autonomous_cycles`,
`cases_worked_last_sweep`, `cases_not_due_last_sweep` and `escalations_raised`.

To watch one cycle without waiting for the cron, use `/fleet-console`, or:

```bash
curl -X POST "$URL/cases/<case-id>/cycle" -H 'content-type: application/json' \
     -d '{"department":"incident-response"}'
curl "$URL/cases/<case-id>/mission"      # the memory it left for the next cycle
```

```bash
gcloud pubsub topics create annaconda-sweeps --project <project>
gcloud pubsub subscriptions create annaconda-sweep-push \
  --topic annaconda-sweeps --push-endpoint "$URL/tasks/sweep" \
  --ack-deadline 120 --project <project>
gcloud scheduler jobs create pubsub annaconda-sweeper --location us-central1 \
  --schedule "*/15 * * * *" --topic annaconda-sweeps --message-body "sweep" \
  --project <project>
# trigger on demand for a demo (Pub/Sub push has a few seconds of latency):
gcloud scheduler jobs run annaconda-sweeper --location us-central1 --project <project>
```

## Requiring a verified identity

By default a tasking may *assert* its department, and every cycle records that
it was asserted. To require a verified Google identity token instead:

```bash
gcloud run services update vigia-live --region us-central1 \
  --set-env-vars VIGIA_REQUIRE_AUTHENTICATED_PRINCIPAL=true,\
VIGIA_DEPARTMENT_ROSTER="analyst@example.com:soc,ir-lead@example.com:incident-response",\
VIGIA_EXPECTED_AUDIENCE="$URL"
```

`VIGIA_EXPECTED_AUDIENCE` is **required** for a token to authenticate at all:
without it the `aud` claim is not checked, so a token minted for another service
would verify. An asserted principal is then refused with 403. A verified
identity wins over whatever the request body claims, so a SOC token cannot run
as forensics. Give
the Pub/Sub push subscription an OIDC token (`--push-auth-service-account`) and
roster that service account, so the cron runs authenticated too. `/health`
reports `requires_authenticated_principal`.

## Known considerations

- The service is deployed `--allow-unauthenticated` for the demo. Agent-mode
  requests trigger billed Vertex calls, so add authentication or rate limiting
  before sharing the URL widely.
- State lives in Firestore whenever `GOOGLE_CLOUD_PROJECT` is set and the
  database is reachable; otherwise the service says so on `/health`
  (`"case_store": "memory"`) and keeps running without durability. The two hash
  chains are stored in bounded segments, so a long-running case is not capped
  by Firestore's 1 MiB per-document limit — which a host under an adjudicated
  malicious verdict, re-checked hourly, would otherwise reach in about eleven
  days.
- Demo evidence is bundled (`tests/fixtures/velociraptor`); swap in the live
  Velociraptor `RestTransport` once a lab endpoint exists.
