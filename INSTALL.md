# Install and run annaconda locally

Linux, macOS and Windows, with the commands for each. Everything below was run
on the platform it is listed under — Windows 11 / Python 3.12.10 and Linux —
rather than inferred from the other.

Cloud Run deployment is a different document: **[DEPLOY.md](DEPLOY.md)**.

---

## What you need

| | |
|---|---|
| **Python** | 3.10 or newer. Tested on 3.12. |
| **git** | to clone. On Windows, Git for Windows also supplies the `bash`, `curl` and `gpg` that the Velociraptor fetch needs. |
| **Nothing else, for the core** | the deterministic engine is stdlib-only by design. `requirements.txt` is the web and agent layer on top of it. |

Optional, and the app states when they are absent rather than pretending:

- **A Gemini API key** — only the agent turns and the narration need it. Every
  sealed verdict is produced *before* any model is called, so without a key the
  deterministic paths run in full and the narration comes back `null`.
- **Google Cloud credentials** — without them the case store degrades to
  in-memory and `/health` reports which backend is live.
- **The Velociraptor binary** — only for live collection from this host. Without
  it the live tests skip, naming the reason.

---

## 1. Clone and create a virtual environment

**Linux / macOS**

```bash
git clone https://github.com/annatchijova/annaconda.git
cd annaconda
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/annatchijova/annaconda.git
cd annaconda
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell refuses the activation script, allow signed local scripts for your
user once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**No Python on Windows?**

```powershell
winget install -e --id Python.Python.3.12
```

Then **close the terminal and open a new one.** The installer writes the new
directories into your persisted user `PATH`, but a shell that was already
running keeps the `PATH` it started with — and until it is refreshed, `python`
resolves to `C:\Users\<you>\AppData\Local\Microsoft\WindowsApps\python.exe`,
the Microsoft Store stub. It is not an interpreter: it answers

```
Python was not found; run without arguments to install from the Microsoft Store
```

which reads like a failed install when the install is fine. `py` will also
report "not recognised" in that stale shell. Both work in a new one.

## 2. Install the dependencies

Same on every platform, inside the activated venv:

```
pip install -r requirements.txt
pip install pytest
```

## 3. Run the tests

**Linux / macOS**

```bash
VIGIA_CASE_BACKEND=memory python3 -m pytest
```

**Windows (PowerShell)**

```powershell
$env:VIGIA_CASE_BACKEND = "memory"
python -m pytest
```

`VIGIA_CASE_BACKEND=memory` keeps the service tests on an in-process store. Set
it whenever `GOOGLE_CLOUD_PROJECT` is in your environment, so the suite does not
read or write real Firestore between runs.

Tests that need something absent skip and say which thing: no Velociraptor
binary, no elevated shell, no PyYAML. A green run never implies a collection
that did not happen.

## 4. Start the service

**Linux / macOS**

```bash
export GEMINI_API_KEY=...        # optional; see above
uvicorn service.app:app --port 8080
```

**Windows (PowerShell)**

```powershell
$env:GEMINI_API_KEY = "..."      # optional; see above
python -m uvicorn service.app:app --host 127.0.0.1 --port 8080
```

Then open <http://127.0.0.1:8080>. `/health` reports which components are live
and which degraded.

> **PowerShell 5.1 trap:** `curl` there is an alias for `Invoke-WebRequest`, so
> `curl -X POST ...` fails with confusing errors. Use `curl.exe` explicitly, or
> the native `Invoke-RestMethod`:
>
> ```powershell
> Invoke-RestMethod "http://127.0.0.1:8080/health" | ConvertTo-Json -Depth 8
> Invoke-RestMethod -Method Post "http://127.0.0.1:8080/injection-demo" | ConvertTo-Json -Depth 8
> ```

---

## Live collection from this host (optional)

This is the part that differs most between platforms.

### Fetch and verify the binary

`scripts/setup_velociraptor.sh` detects your OS and architecture, downloads the
matching official release, and refuses to install it unless the signature
carries the pinned Velocidex fingerprint.

**Linux / macOS**

```bash
scripts/setup_velociraptor.sh
```

**Windows** — run it from **Git Bash**, not PowerShell; it needs `bash`, `curl`
and `gpg`, all of which Git for Windows installs:

```bash
scripts/setup_velociraptor.sh
```

Set `VELOCIRAPTOR_PLATFORM` to fetch for a different target (for example
`VELOCIRAPTOR_PLATFORM=windows-amd64` from Linux).

### Run the collection

**Linux / macOS**

```bash
python3 scripts_lib/live_velociraptor_demo.py
python3 scripts_lib/windows_live_collect.py <path-to-velociraptor> --show-fields
```

**Windows — needs an elevated terminal.** The Windows release embeds
`requestedExecutionLevel="highestAvailable"`, so an unelevated shell gets
`ERROR_ELEVATION_REQUIRED (740)` and the binary never starts — not even for
`version`. Open Terminal as Administrator (Win+X, then A):

```powershell
cd C:\path\to\annaconda
python scripts_lib\live_velociraptor_demo.py
python scripts_lib\windows_live_collect.py tools\velociraptor\velociraptor-v0.77.1-windows-amd64.exe --show-fields
```

`--show-fields` prints the field names **and types** Velociraptor actually
returned, which is how you correct a template against real data instead of
guessing at it.

Take the dump home and re-derive the same artifacts from the same rows:

```
python scripts_lib\windows_live_collect.py --replay evidence_dump\
```

---

## Platform differences, in one table

Everything else is identical.

| | Linux / macOS | Windows |
|---|---|---|
| Interpreter | `python3` | `python` (`py -3` to create the venv) |
| Activate venv | `source .venv/bin/activate` | `.\.venv\Scripts\Activate.ps1` |
| Set a variable | `export NAME=value` | `$env:NAME = "value"` |
| Path separator | `scripts_lib/x.py` | `scripts_lib\x.py` |
| `scripts/setup_velociraptor.sh` | any shell | **Git Bash** |
| Velociraptor asset | `velociraptor-v<ver>-linux-amd64` | `velociraptor-v<ver>-windows-amd64.exe` |
| Live collection | normal shell | **elevated shell** (UAC) |
| HTTP from the shell | `curl` | `curl.exe` or `Invoke-RestMethod` |

### Two things that are weaker on Windows, and say so

Neither is silent, and neither touches a sealed value:

- **Subprocess resource limits.** `setrlimit` is POSIX-only, so the sandbox
  cannot cap a child's memory or CPU on Windows. It warns once at import and
  falls back to an aggressive timeout. Set `VIGIA_ENFORCE_POSIX_SANDBOX=true` to
  refuse to run at all rather than continue without them.
- **Audit-log write serialization.** `fcntl.flock` is POSIX-only, so concurrent
  writers are not serialized on Windows. It warns once; use single-process mode
  there, or deploy on POSIX.

`security.safe_grep` also depends on GNU `find`/`xargs`/`grep`. Windows resolves
the bare name `find` to `System32\find.exe`, an unrelated tool, so the search
fails — loudly, reported as a failed scan rather than an empty directory.

---

## If something does not work

| Symptom | Cause |
|---|---|
| `ModuleNotFoundError: core` / `tools` | Run from the repository root, or with the venv activated. |
| `ERROR_ELEVATION_REQUIRED (740)` | Velociraptor on Windows needs an elevated terminal. |
| Live tests skip | Expected. The skip reason names what is missing — the binary, or the right to start it. |
| `/consult` returns 503 | No model reachable. Set `GEMINI_API_KEY`. The sealed verdict path does not need one. |
| Firestore errors | None needed. Set `VIGIA_CASE_BACKEND=memory` for the in-process store. |
| `Invoke-WebRequest` errors from a `curl` command | PowerShell 5.1 aliases `curl`. Use `curl.exe`. |
