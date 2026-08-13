"""VIGIA live purple-team agent (Google ADK + Gemini).

The agent drives the investigative loop — it chooses which curated hunts to
run, decides when to freeze and adjudicate an evidence window, and explains
sealed results to the examiner. It does NOT decide the verdict: adjudication
runs the deterministic core inside a tool and returns a sealed, chained
result the model cannot alter. This is VIGIA's invariant expressed at the
agent layer — the LLM acts and guides, it never decides.

Split:
- tools.py: deterministic tool layer (no ADK/Gemini import; fully testable).
- purple_team_agent.py: the ADK Agent wiring (imports google.adk).
"""
