# Reproducción — Red Team Ronda 2

Cada script imprime su **predicción antes del resultado**. Todos corren offline
(stdlib + `fastapi` para los que usan `TestClient`); ninguno necesita
credenciales, red, ni `google-adk`.

```bash
cd <repo-root>
PYTHONPATH=. python3 docs/redteam/repro/<script>.py
```

| Script | Hipótesis | Hallazgo |
|---|---|---|
| `e1_commander_dept.py` | H1 | A-9 · el `fleet-commander` nunca se autoriza contra el catálogo |
| `e2_identity_matrix.py` | H5 | A-5 · matriz (token × dept reclamado) → dept efectivo |
| `e3_abstain.py` | H4 | bucle de recolección fallida (2 h, sin escalación) |
| `e3b_abstain.py` | H4 | A-4 · 8 ciclos `ABSTAIN`, 0 escalaciones, `stand_down` permitido |
| `e4_abstain_to_benign.py` | H4 | A-6 · `status='benign'` con `worst_verdict='ABSTAIN_*'` |
| `e5_memory_seal.py` | H3 | A-8 · el estado operativo queda fuera del sello |
| `e6_identity_substitution.py` | H2 | A-1 · exhibit reetiquetado → `PASS` |
| `e6b_with_windows.py` | H2 | A-1 · con windows y `--strict` → `PASS` sin WARN |
| `e7_escalation_suppress.py` | H1 | A-2 · el orden de dos llamadas permitidas suprime la escalación del motor |
| `e8_endpoints.py` | H1 | A-3 · el catálogo cubre 1 de 5 caminos al núcleo sellado |
| `e9_falsify.py` | — | vectores **falsados** + retraso indefinido sobre `ABSTAIN_DEGRADED` |
| `e10_ack_toctou.py` | H2 | A-7 · reconocimiento posicional + desalojo de la escalación `MALICE` |

`abstain_fix/` es el fixture derivado de `tests/fixtures/velociraptor` con
`analysis_status: PENDING` en cada fila (la compuerta de intake documentada en
`tools/velociraptor/adapter.py:54`), para que cada ciclo selle `ABSTAIN_*`.

`e6*.py` escriben sus exhibits en el directorio de trabajo actual.
