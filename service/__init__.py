"""VIGIA live purple-team backend service (FastAPI, for Cloud Run).

Wraps the deterministic forensic core and the ADK+Gemini agent behind an HTTP
API so the whole system runs as a Google Cloud Run backend. Two investigation
modes: 'scripted' runs the sealed hunt/adjudicate loop with no LLM (fast,
free, deterministic — the replay/dashboard path), 'agent' lets the ADK agent
drive and narrate. Either way the verdict is sealed by the core, never by the
caller.
"""
