# Auditoría de seguridad — ANNACONDA

## Red Team Ronda 2 — fracturas arquitectónicas y de composición

**Fecha:** 2026-08-23
**Método:** Ingeniería abductiva (A–D–I) + Red-Team Auditing
**Base:** `claude/annaconda-architecture-security-7f3u1l` @ `3f2c19c`
**Runtime:** CPython 3.11.15, stdlib + fastapi 0.136.3. `google-adk` / `google-auth` /
`google-cloud-firestore` ausentes en el sandbox (21 de las pruebas del repo son
errores/fallos de *colección* por esa ausencia; el resto pasa — ninguna prueba
falla por lógica).
**Evidencia reproducible:** `docs/redteam/repro/e*.py` — cada script imprime su
predicción antes del resultado.

**Alcance.** No es un code review. Se atacó una única afirmación:
*ningún camino controlado por el agente puede alterar el objeto que determina el
veredicto final*, sobre las cinco hipótesis pedidas.

---

## Modelo de amenaza

El atacante **PUEDE**:
- emitir peticiones HTTP arbitrarias al servicio (los endpoints son públicos en el
  despliegue demo: `POST /cases`, `/cases/{id}/investigate`, `/cases/{id}/cycle`,
  `/cases/{id}/escalations/{i}/acknowledge` no piden credencial);
- elegir el `department` que declara, y elegir **no** enviar `Authorization`;
- influir sobre el turno del modelo comandante (inyección vía la evidencia que el
  endpoint recolecta, o simplemente un modelo que se equivoca de orden);
- editar el JSON de un *exhibit* ya exportado (es un fichero que se entrega).

El atacante **NO PUEDE**:
- modificar el código ni el registro sellado de agentes;
- alterar una window sellada ni una entrada de la cadena (**falsado**, ver §F);
- mover un veredicto ya sellado (**falsado**, ver §F).

**Bucket** por hallazgo: `vuln` (defecto explotable dentro del modelo) ·
`precondición` (cierto pero exige una capacidad que ya es game-over) ·
`higiene`.

## Leyenda epistémica

`CODE FACT` · `HIPÓTESIS PLAUSIBLE` · `CONFIRMADO POR INDUCCIÓN` · `FALSADO`

Nada aquí lleva CONFIRMADO sin un experimento ejecutado cuya predicción se
escribió antes del resultado.

---

## Resumen ejecutivo

| ID | Sev | Nivel | Hip. | Módulo | Hallazgo |
|----|-----|-------|------|--------|----------|
| A-1 | **Alta** | CONFIRMADO POR INDUCCIÓN | H2 | `verify_bundle` / `verdict_stream` | El sello no compromete el **host**, y ningún verificador compara el `case_id` sellado con el del sobre. Un exhibit `MALICE_HIGH` reetiquetado a otro host/caso/perito da `PASS` estricto. |
| A-2 | **Alta** | CONFIRMADO POR INDUCCIÓN | H1 | `agent/autonomy.py` | La escalación obligatoria del motor ante `MALICE` se suprime **reordenando dos llamadas permitidas**. |
| A-3 | **Alta** | CONFIRMADO POR INDUCCIÓN | H1 | `service/app.py` | El catálogo cubre 1 de 5 caminos al núcleo sellado. El mismo efecto que niega a `soc` en `/cycle` es incondicional y anónimo en `/cases/{id}/investigate`. |
| A-4 | **Alta** | CONFIRMADO POR INDUCCIÓN | H4 | `agent/autonomy.py` | `ABSTAIN → ABSTAIN → …` indefinido, 0 escalaciones; y `stand_down` está **permitido** sobre un caso cuyo registro sellado dice "los analizadores estaban desactivados, el resultado no es fiable". |
| A-5 | Media-alta | CONFIRMADO POR INDUCCIÓN | H5 | `agent/principal.py` | Inversión de monotonía: un token **válido no rosterizado** → 403; **sin token** → permitido, y como `incident-response`, el departamento más privilegiado del catálogo (9/9 agentes). |
| A-6 | Media-alta | CONFIRMADO POR INDUCCIÓN | H4 | `service/case_store.py` | `status` pasa a `benign` mientras `worst_verdict` sigue siendo `ABSTAIN_*`. "No lo pudimos ver" se muestra como "estaba limpio". |
| A-7 | Media | CONFIRMADO POR INDUCCIÓN | H2 | `service/app.py` + `agent/mission.py` | La defensa de id estable al reconocer escalaciones es **inalcanzable**: la ruta tipa `index: int`. Y `_trim` desaloja la escalación `MALICE` no reconocida antes que notas rutinarias más nuevas. |
| A-8 | Media | CONFIRMADO (propiedad) / precondición | H3 | `agent/mission.py` | `verify_mission` sella el **diario**, no el **estado que el sistema lee**. Reescribir `standing_down` / `tried_hunts` deja `memory_ok: True` y cambia qué evidencia llega a existir. |
| A-9 | Baja | CONFIRMADO POR INDUCCIÓN | H1 | `agent/autonomy.py` | El `fleet-commander` nunca se autoriza a sí mismo contra el catálogo: `training` y `compliance` ejecutan ciclos completos y escriben `case_memory`. |

---

## A-1 · El sello no ata el veredicto a la máquina que juzgó

**Severidad:** Alta · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Bucket:** vuln
**Hipótesis:** H2 (identity substitution) · **Repro:** `repro/e6_identity_substitution.py`, `repro/e6b_with_windows.py`

**Invariante afirmada.** `GET /cases/{id}/exhibit` (`service/app.py:512-549`):
*"Carries the sealed verdict chain and the case metadata needed to re-derive every
seal without this service… this exhibit proves INTEGRITY — nothing was altered,
reordered, inserted, or dropped after sealing."* Y `tools/verify_bundle.py:1-30`
se declara *"court-grade, adversarial verifier… trusting nothing"*.

**Sorpresa.** El sello compromete `case_id`, pero el objeto que un juez lee para
saber **de qué máquina** habla el veredicto es el sobre, no el sello.

**Abducción (rivales, por economía de investigación).**
1. El `entry` sella el host → no hay sustitución. *(refutada abajo)*
2. El `entry` no sella el host, pero el verificador compara `window["host"]`
   con el sobre → sustitución detectada. *(refutada abajo)*
3. El `entry` no sella el host y nadie compara → sustitución de identidad.

**Deducción (predicción, escrita antes de correr).**
Si (3), entonces: (P1) ningún campo sellado nombra el host; (P2) reescribir
`case.host` / `case.examiner_id` en el exhibit da `PASS`; (P3) reescribir además
`case.case_id` da `PASS` aunque cada entrada sellada lleve otro `case_id` dentro.

**Inducción (ejecutado).**

```
P1 campos que sella la entrada: ['bundle_sha256','canonicalize_version','case_id',
                                 'prev_entry_hash','schema_version','sequence',
                                 'verdict','window_hash']
P1 ¿algún campo sellado nombra el host?  False

entry['case_id'] dentro de la cadena sellada : CASE-VICTIM-A
el sobre ahora declara case.case_id          : CASE-INNOCENT-B

annaconda-verify exhibit_relabelled_case.json
  annaconda exhibit verification: PASS (with warnings)
  case:    CASE-INNOCENT-B          <-- la identidad reescrita, impresa como verdad
  entries: 1 sealed verdict(s) in the chain
  exit=0
```

Y con las **windows incluidas** y `--strict` (cierra la objeción "exportá el
exhibit completo") — `repro/e6b_with_windows.py`:

```
el sobre declara      host = WIN11-INNOCENT-B   case = CASE-INNOCENT-B
la window sellada dice host = WIN11-VICTIM-A    case = CASE-VICTIM-A
la entrada sellada dice                         case = CASE-VICTIM-A

annaconda-verify --strict exhibit_full_relabelled.json
  annaconda exhibit verification: PASS      <-- ni un WARN
  case:    CASE-INNOCENT-B
  The chain is intact: no verdict was altered, reordered, inserted, or dropped.
  exit=0
```

El verificador tiene **las dos identidades en la mano** y no las compara.

**Cadena causal.**

```
build_stream_entry  (core/verdict_stream.py:103-121)
    sella case_id, sequence, window_hash, verdict — NUNCA el host
        ↓
GET /cases/{id}/exhibit  (service/app.py:537-545)
    emite case.host / case.case_id / case.examiner_id FUERA de todo sello
        ↓
verify_entries  (tools/verify_bundle.py:151-197)
    busca la window por window_hash y la re-sella; no compara window["host"]
    ni window["case_id"] con el sobre, ni entry["case_id"] con case["case_id"]
        ↓
verify_bundle  (tools/verify_bundle.py:213)
    report["case_id"] = case["case_id"]   <-- toma la etiqueta mutable
        ↓
_render  (tools/verify_bundle.py:226)
    imprime "case: <etiqueta del atacante>" junto a PASS
```

`core/verdict_stream.py:124-157` (`verify_stream`, el verificador del propio
servicio) tiene el mismo hueco: recorre las entradas y nunca mira `case_id`.

**Precondición.** El atacante edita un exhibit ya exportado — es decir, un
fichero que el sistema entrega precisamente para que terceros lo verifiquen sin
confiar en el servicio. No requiere acceso al servicio ni a la clave.

**Redacción precisa.** El sello **no se rompió**. Lo que se demuestra es que la
garantía que el sello ofrece es más estrecha que la que el exhibit anuncia: prueba
que *esta cadena de veredictos* es íntegra, no que *esta cadena pertenece a esta
máquina y a este caso*.

---

## A-2 · La escalación obligatoria del motor se suprime reordenando llamadas permitidas

**Severidad:** Alta · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Bucket:** vuln
**Hipótesis:** H1 (composición de herramientas permitidas) · **Repro:** `repro/e7_escalation_suppress.py`

**Invariante afirmada.** `agent/autonomy.py:524-527`:
*"A malicious verdict reaches a human because the ENGINE reached it, not because
the commander chose to say so… a cycle that seals MALICE and tells nobody is the
failure this whole system exists to prevent. Raised here, from the sealed record,
with the basis attached mechanically."*

**Sorpresa.** La red de seguridad está condicionada a un estado que el propio
comandante puede fijar con una herramienta que sí tiene:

```python
# agent/autonomy.py:535
if malice and not mem.has_open_escalation(mission):
```

**Abducción.** El comandante no posee ninguna herramienta para suprimir la
escalación del motor. Pero `escalate_to_human` es suya, y deja una escalación
**no reconocida**, que es exactamente lo que `has_open_escalation` mide.

**Deducción (predicción).** El orden importa. `escalate_to_human` **antes** de
`request_adjudication` es una secuencia de llamadas permitidas en un orden
permitido; deja `has_open_escalation() == True` cuando el motor comprueba, así
que la escalación del motor no se dispara, y lo único que un humano ve lleva
`sealed_basis: []`, `unsupported_by_seal: True`, y no nombra el `MALICE`.

**Inducción (ejecutado, mismo host, mismo veredicto sellado).**

```
=== orden = adjudicate-first
    veredicto sellado                  : MALICE_HIGH
    escalación obligatoria del motor   : True
    lo que ve el humano:
      why                : 'the sealed engine adjudicated MALICE_HIGH'
      sealed_basis       : [{'verdict_state': 'MALICE_HIGH', 'entry_hash': 'ef59…', 'sequence': 0}]
      unsupported_by_seal: False
      ¿nombra el veredicto?: True

=== orden = escalate-first
    veredicto sellado                  : MALICE_HIGH
    escalación obligatoria del motor   : False        <-- no se disparó
    lo que ve el humano:
      why                : 'routine note: continuing to observe this host'
      sealed_basis       : []
      unsupported_by_seal: True
      ¿nombra el veredicto?: False
    verify_mission memory_ok           : True
```

**Cadena causal.**

```
escalate_to_human(...)                     herramienta permitida del comandante
    ↓  mission["escalations"].append({... "acknowledged": False})
has_open_escalation(mission) == True       agent/mission.py:453-463
    ↓
request_adjudication(...)  →  MALICE_HIGH sellado
    ↓
if malice and not has_open_escalation(mission)   agent/autonomy.py:535
    ↓  la condición es False
la escalación con sealed_basis mecánico NUNCA se crea
    ↓
mission["escalation"] = _current_escalation()    agent/mission.py:466-477
    ↓  única candidata: la nota rutinaria, rank 0
el humano lee una escalación que no menciona el veredicto malicioso
```

**Nota de honestidad — mitigaciones que siguen en pie.** `worst_verdict` y
`status` del caso sí dicen `malice`; `_sweep_priority` lo pone primero; y el push
a SecOps se dispara igual porque `result["escalation"]` no es `None`. Lo que se
pierde es el canal que la arquitectura declara *como* la garantía: la escalación
con la base sellada adjunta mecánicamente. El comentario de `agent/autonomy.py:528-532`
identifica el caso *reconocido*; el hueco es el caso *no reconocido*.

**Corolario (mismo mecanismo, sin agente hostil).** Como las escalaciones
persisten entre ciclos, cualquier escalación abierta de un ciclo anterior suprime
la del motor en el ciclo que sella `MALICE`.

---

## A-3 · El catálogo cubre 1 de 5 caminos al núcleo sellado

**Severidad:** Alta · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Bucket:** vuln
**Hipótesis:** H1 (endpoints humanos vs internos) · **Repro:** `repro/e8_endpoints.py`

**Invariante afirmada.** `agent/catalog.py:12-14`: *"This module is that layer,
and it is a gate, not documentation: `authorize` refuses a tasking that the
catalog does not permit, and the refusal is the mechanism, not a prompt
instruction the model could talk itself out of."* Y `service/app.py:274-276`:
*"the SOC may task the collectors, but adjudication belongs to forensics."*

**CODE FACT.** `catalog.authorize` se invoca desde exactamente dos sitios, ambos
dentro de `agent/autonomy.py` (`:180` y `:209`), es decir dentro de
`commander_tools`. Los demás caminos a `session.adjudicate()` —
`POST /investigate` (`app.py:339`), `POST /cases/{id}/investigate` (`app.py:552`),
`POST /fleet-investigate` (`app.py:663`), `POST /injection-demo` (`app.py:678`) y
`agent.fleet.dispatch_investigation` (`fleet.py:137`) — no consultan ni el
catálogo ni un principal.

**Deducción (predicción).** `POST /cases/{id}/investigate` alcanza el efecto del
`correlator` (`reaches_sealed_core: True`, `available_to: [forensics,
incident-response]`) sin cabecera `Authorization`, sin departamento y sin llamada
al catálogo.

**Inducción (ejecutado, lado a lado).**

```
el catálogo dice quién alcanza el núcleo sellado:
   correlator.available_to        = ['forensics', 'incident-response']
   correlator.reaches_sealed_core = True
   ¿SOC puede tasquear al correlator? = False

POST /cases                       -> 200   (sin cabecera de auth)
POST /cases/E8/investigate        -> 200   (sin cabecera de auth)
   veredicto sellado añadido      : ['MALICE_HIGH']
   entry_hash                     : b2ea3232d1f63b928d988155 ...
GET  /cases/E8/exhibit            -> 200  chain_ok = True

POST /cases/E8B/cycle {'department':'soc'} -> 200
   rechazos del catálogo          : ["agent 'correlator' is not published to
                                      department 'soc' (published to …"]
   veredictos sellados este ciclo : []
```

El mismo efecto que el catálogo **niega** a `soc` por el camino agéntico es
**incondicional y anónimo** por el camino humano.

**Redacción precisa.** No es "el catálogo tiene un bypass". Es: el catálogo es un
gate real sobre el camino agéntico y **documentación** sobre los otros cuatro. La
frase "gate, not documentation" es verdadera de `commander_tools` y falsa del
sistema.

---

## A-4 · ABSTAIN es un ciclo absorbente, y se puede aparcar

**Severidad:** Alta · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Bucket:** vuln
**Hipótesis:** H4 · **Repro:** `repro/e3b_abstain.py`, `repro/e9_falsify.py`

**Deducción (predicción).** Un host que adjudica `ABSTAIN_*` en cada ciclo hace
bucle `ABSTAIN → schedule → ABSTAIN → …` indefinidamente, con **cero**
escalaciones; y como `is_compromised` solo prueba `MALICE`/`ESCALATE`,
`stand_down` está **permitido** sobre él.

**Inducción (8 ciclos, fixture que sella `ABSTAIN_INSUFFICIENT` siempre).**

```
ciclo  sellado                 worst                 escal  stand_down  next  decisión
1      ABSTAIN_INSUFFICIENT    ABSTAIN_INSUFFICIENT  0      False       6h    ['schedule_next_cycle']
2      ABSTAIN_INSUFFICIENT    ABSTAIN_INSUFFICIENT  0      False       6h    ['schedule_next_cycle']
…                                                    (idéntico hasta el 8)
8      ABSTAIN_INSUFFICIENT    ABSTAIN_INSUFFICIENT  0      False       6h    ['schedule_next_cycle']

escalaciones en 8 ciclos             : 0
¿algún humano fue notificado?        : False
is_compromised(caso ABSTAIN)         : False
→ stand_down() permitido             : True

stand_down() sobre el caso ABSTAIN   : {'rationale': 'the host has been quiet; nothing
                                        further to collect', 'at_cycle': 8, …}
is_due tras stand_down               : False       <-- el sweep no vuelve nunca
verify_mission tras stand_down       : True
```

Y el retraso indefinido (`repro/e9_falsify.py`), sobre `ABSTAIN_DEGRADED` —
que `service/case_store.py:143-146` define como *"Critical analyzers were disabled
during analysis; the result is unreliable"*:

```
is_compromised(caso ABSTAIN_DEGRADED)  : False
schedule_next_cycle(720h)              -> {"in_hours": 720, "due_utc": …}   ACEPTADO
la misma llamada sobre un caso MALICE  -> {"error": "this host's sealed record is
                                            malicious, so it cannot be scheduled
                                            more than 2h out…"}
```

**Cadena causal.**

```
plan_deterministically  (agent/autonomy.py:426-458)
    if   state.startswith("MALICE")   → escalate_to_human + 1h
    elif compromised                  → 1h
    elif state.startswith("ABSTAIN")  → schedule 6h        <-- nunca escala
    elif state.startswith("BENIGN") and cycles>=3 → stand_down
    else                              → 24h
        ↓
is_compromised  (agent/autonomy.py:124-135)  prueba solo MALICE / ESCALATE
        ↓
stand_down  (agent/autonomy.py:310-315)      gate = is_compromised → permitido
schedule_next_cycle (agent/autonomy.py:261)  cap 2h = is_compromised → sin cap
        ↓
mem.stand_down → mission["standing_down"]  →  is_due() == False para siempre
```

La asimetría: `MALICE` escala de inmediato, `BENIGN` cierra tras 3 ciclos, y
`ABSTAIN` —el estado que existe precisamente para decir "no puedo afirmarlo"— ni
escala, ni cierra, ni tiene techo de intervalo. Es el único estado sin salida
hacia un humano.

---

## A-5 · Identidad declarada vs efectiva: presentar una credencial válida es peor que no presentar ninguna

**Severidad:** Media-alta · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Bucket:** vuln
**Hipótesis:** H5 · **Repro:** `repro/e2_identity_matrix.py`

**Matriz completa (token × departamento reclamado → departamento efectivo).**

| Estado del token | Reclama | Dept. efectivo | `authenticated` | `identity` almacenada | Resultado |
|---|---|---|---|---|---|
| ausente | *(ninguno)* | **incident-response** | False | None | **ALLOWED** |
| ausente | `forensics` | forensics | False | None | ALLOWED |
| malformado (no `Bearer`) | cualquiera | lo reclamado | False | None | ALLOWED |
| `Bearer` basura | cualquiera | lo reclamado | False | None | ALLOWED |
| expirado | cualquiera | lo reclamado | False | None | ALLOWED |
| audiencia incorrecta | cualquiera | lo reclamado | False | None | ALLOWED |
| **válido, rosterizado** | `soc` | forensics *(el roster gana)* | True | alice@… | ALLOWED |
| **válido, NO rosterizado** | cualquiera | **None** | False | mallory@evil.com | **403 REFUSED** |

**El bug no es un auth bypass** — es que la última fila está *invertida* respecto
de las cinco anteriores. Un atacante con un token real que este despliegue no
rosteriza obtiene **más** acceso **borrando la cabecera**. La credencial válida es
el único input que cierra la puerta.

**Y el default es el máximo privilegio.** Cuántos agentes puede tasquear cada
departamento del catálogo:

```
{'incident-response': 9, 'soc': 7, 'forensics': 7, 'training': 1}
```

`service/app.py:957` fija `default_department=autonomy.COMMANDER_DEPARTMENT`
(`"incident-response"`). La identidad efectiva de un llamante **anónimo** es el
departamento más privilegiado del despliegue.

**Además:** `principal.resolve` nunca valida el departamento reclamado contra
`catalog.DEPARTMENTS`:

```
claimed_department='; DROP TABLE --'
 -> {'department': '; drop table --', 'identity': None, 'authenticated': False,
     'how': 'asserted in the request, no verified identity'}
¿es un departamento publicado? False
```

Ese string entra en `mem.begin_cycle` (`agent/mission.py:602-620`) y queda
**sellado en el diario de la misión** como el departamento que corrió el ciclo.
El registro lo marca `authenticated: False`, así que no miente — pero la
identidad *registrada* y la identidad *autenticada* divergen por diseño y sin
validación de dominio.

**Cadena causal.**

```
principal.resolve  (agent/principal.py:119-149)
   email verificado y rosterizado  → dept del roster, authenticated=True
   email verificado NO rosterizado → dept=None            (línea 143)
   sin email (ausente/inválido/expirado/audiencia mala)
                                   → dept = reclamado o default  (línea 146-149)
        ↓
principal.enforce  (agent/principal.py:152-162)
   if not principal["department"]: raise  ← SOLO dispara en el caso verificado
        ↓
_principal_for  (service/app.py:946-961)  →  403 exclusivamente para
                                             quien presentó una credencial real
```

**Precondición.** `VIGIA_REQUIRE_AUTHENTICATED_PRINCIPAL` sin fijar — que es la
postura por defecto y la documentada para el demo desplegado
(`agent/principal.py:17-27`).

---

## A-6 · "No lo pudimos observar" se muestra como "estaba limpio"

**Severidad:** Media-alta · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Bucket:** vuln
**Hipótesis:** H4 · **Repro:** `repro/e4_abstain_to_benign.py`

**Invariante afirmada.** `service/case_store.py:190-193`: *"Reflect the conclusion
the reentry reached — but NEVER downgrade a case that already has a worse verdict
in its history."*

**Inducción (ejecutado).**

```
rangos: ABSTAIN_INSUFFICIENT=3  BENIGN_MEDIUM=2  BENIGN_HIGH=1

run 1 — la recolección no pudo concluir:
  status='abstain'  worst_verdict='ABSTAIN_INSUFFICIENT'  open_question=open
run 2 — una ventana posterior vuelve limpia:
  status='benign'   worst_verdict='ABSTAIN_INSUFFICIENT'  open_question=resolved

RESULTADO: status y worst_verdict DISCREPAN.

fila que ve el analista (_summarize):
  status         : benign
  worst_verdict  : ABSTAIN_INSUFFICIENT
  open_questions : 0
```

**Cadena causal.**

```
_apply_run  (service/case_store.py:216-225)
    worst = ABSTAIN_INSUFFICIENT  →  case["status"] = "abstain"     (correcto)
        ↓
_update_open_question  (service/case_store.py:180-196)
    concluded = "BENIGN_HIGH" (¡de OTRA ventana, otra superficie!)
    q["resolved"] = True                        ← la pregunta abierta se cierra
    if not (worst.startswith("MALICE") or worst == "ESCALATE"):
        case["status"] = "benign"               ← sobrescribe el status honesto
        ↓
la guarda protege contra degradar MALICE, no contra degradar ABSTAIN
        ↓
plan_deterministically  (agent/autonomy.py:449)
    state BENIGN + unresolved vacío + cycles>=3  →  stand_down()
```

La pregunta "¿era maliciosa la superficie que no pudimos recolectar?" se marca
resuelta por "recolectamos **otra** superficie y salió limpia". Esa es
exactamente la equivalencia semántica que la hipótesis 4 buscaba.

---

## A-7 · La defensa de id estable al reconocer escalaciones es inalcanzable, y `_trim` desaloja la escalación que importa

**Severidad:** Media · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Bucket:** vuln
**Hipótesis:** H2 · **Repro:** `repro/e10_ack_toctou.py`

**Invariante afirmada.** `agent/mission.py:558-563` nombra el peligro y dice
haberlo cerrado: *"`index` may be a stable escalation id ("E3") or a position.
Prefer the id: the list is capped by `_trim`, so a position a caller read a moment
ago can point at a different escalation by the time it is used — and taking up the
wrong one silences an escalation nobody handled."*

**CODE FACT.** El único llamante es `service/app.py:1028`:
`async def acknowledge_escalation(case_id: str, index: int, …)`.

**Inducción (ejecutado).**

```
escalación del motor creada, id estable = E1

POST /cases/E10/escalations/E1/acknowledge  -> 422   (la ruta rechaza el id estable)
POST /cases/E10/escalations/0/acknowledge   -> 200   (solo posicional)
   acknowledged_by               : alice        ← texto libre elegido por quien llama
   acknowledged_by_authenticated : False        ← sin cabecera Authorization

tras 56 escalaciones, len(lista) = 50
   ¿sigue la escalación MALICE del motor (E1)?  False
   summarized_away: {'escalations': 6}
   ahora en POSICIÓN 0 : 'routine note 5'   | sealed_basis: []
```

Dos defectos compuestos:

1. **La corrección existe en `mission.py` y es inalcanzable desde la API.** El
   tipado `int` de FastAPI convierte la rama de id estable en código muerto: el
   reconocimiento es posicional, que es el fallo que el comentario declara
   resuelto.
2. **`_trim` desaloja por antigüedad, no por severidad.** `cap()`
   (`agent/mission.py:101-120`) ordena por `(settled, índice)` y no consulta
   `_escalation_rank` (`agent/mission.py:437-450`), que existe precisamente para
   decir cuál importa. Una escalación **no reconocida** con base sellada
   `MALICE_HIGH` se descarta antes que notas rutinarias más nuevas.
   `escalate_to_human` es una herramienta del comandante sin límite por ciclo.

Y el reconocimiento —lo que hace que una escalación por veredicto malicioso deje
de pedir atención— no exige credencial: `_principal_for(request)` sin `claimed`
resuelve a `incident-response` asertado, y el `actor` registrado es el
`examiner_id` que el llamante escribe.

---

## A-8 · `verify_mission` sella el diario, no el estado que el sistema lee

**Severidad:** Media · **Nivel:** CONFIRMADO (la propiedad) / precondición (la explotación) · **Bucket:** vuln con precondición
**Hipótesis:** H3 · **Repro:** `repro/e5_memory_seal.py`

**Invariante afirmada.** `agent/mission.py:16-21`: *"It is tamper-evident. **Every
mutation** appends a journal entry sealed over the previous one… Memory that
survives weeks is memory an attacker has weeks to edit; `verify_mission` proves
nobody did. Rewriting or reordering the fleet's own history breaks the chain."*

**Inducción (ejecutado).**

```
campos que el sello del diario compromete:
   ['action','actor','cycle','detail','prev_hash','recorded_utc','seq']

standing_down falsificado (diario intacto)
   verify_mission memory_ok : True      errores: []
   memory_head sin cambios  : True
   is_due(alterado)         : False     ← el sweep no despierta más este caso
   ¿el diario dice stand_down? : False

tried_hunts falsificado (diario intacto)
   verify_mission memory_ok : True
   objetivo del planner, honesto : persistence-agent
   objetivo del planner, alterado: windows-hunter
                                  ← la superficie de persistencia no se recolecta nunca
```

**Campos que el sistema LEE y que ningún hash cubre:** `standing_down`,
`next_action`, `tried_hunts`, `hypotheses`, `open_questions`, `escalations`,
`escalation`, `cycles`, `summarized_away`.

**Cadena causal (H3 tal como se planteó: la memoria cambia qué evidencia llega a existir).**

```
mission["tried_hunts"]  (no cubierto por ningún sello)
    ↓  plan_deterministically  (agent/autonomy.py:377-385)
       collected = {tuple(t["hunts"]) for t in mission["tried_hunts"]}
    ↓  la superficie marcada como "ya cubierta" no se elige nunca
la evidencia de persistencia NUNCA SE RECOLECTA
    ↓  el motor no puede adjudicar lo que nunca existió
```

```
mission["standing_down"]  (no cubierto por ningún sello)
    ↓  is_due()  (agent/mission.py:632-633)  → False incondicional
el sweep no vuelve a tocar el caso, para siempre
    ↓  verify_mission() sigue diciendo memory_ok: True
```

**Precondición honesta.** Requiere escritura sobre el documento del caso
(Firestore, o el store en memoria). Ningún endpoint HTTP ofrece esa escritura
arbitraria hoy. Lo que está **confirmado sin precondición** es la afirmación de
alcance: `verify_mission` no prueba lo que su docstring dice que prueba. Es un
hueco de frontera de confianza (el estado operativo vive fuera del perímetro
criptográfico), no un exploit ya alcanzable.

---

## A-9 · El `fleet-commander` nunca se autoriza contra el catálogo

**Severidad:** Baja · **Nivel:** CONFIRMADO POR INDUCCIÓN · **Bucket:** vuln
**Hipótesis:** H1 · **Repro:** `repro/e1_commander_dept.py`

`catalog.authorize` se llama para los *delegados* (`agent/autonomy.py:180`, `:209`)
y nunca para el *delegante*. `fleet-commander.available_to = [soc,
incident-response, forensics]` no se aplica.

```
dept=training     publicado_para_commander=False  acted=True cycle=1
                  journal_entries=3  next_action=set
                  rechazos del catálogo: ['refused_by_catalog']   ← solo el colector
dept=compliance   publicado_para_commander=False  acted=True cycle=1
                  journal_entries=3  next_action=set
```

`training` y `compliance` abren un ciclo, sellan tres entradas de diario y fijan
el próximo despertar del caso — escribiendo `case_memory`, una clase de datos que
el catálogo no les concede. Baja porque las herramientas propias del comandante
son solo de memoria; pero `available_to` sobre el comandante es decorativo, y
`delegates_to` (`agent/catalog.py:156`) tampoco se comprueba en ningún sitio.

---

## Vectores descartados (falsados) — la parte que le da dientes al método

| Vector | Predicción | Resultado | Por qué falló |
|---|---|---|---|
| Adjudicar una window manipulada (`raw_score` inflado in situ) | quizá pasa | **FALSADO** | `verify_window` recomputa el hash; `adjudicate` devuelve *"window failed its seal check — refusing to adjudicate tampered evidence"* (`agent/tools.py:207-209`) |
| Envenenar la memoria de misión y luego adjudicar | quizá mueve el veredicto | **FALSADO** | `MALICE_HIGH` idéntico. `window_to_case` no alimenta memoria al scorer; el sello se calcula antes de que ningún modelo hable |
| Acuñar una entrada con `prev_entry_hash` forjado | quizá encadena | **FALSADO** | `build_stream_entry` exige GENESIS en `sequence` 0 (`core/verdict_stream.py:89-90`) |
| `soc` pidiendo adjudicación vía `/cycle` | quizá escala privilegio | **FALSADO** | El catálogo la rechaza correctamente — el camino agéntico está bien cerrado (por eso A-3 es sobre los otros cuatro) |
| Departamento arbitrario (`"root"`) llegando al catálogo | quizá pasa | **FALSADO** | `_norm_department` lo rechaza (`agent/catalog.py:201-207`). Sí queda sellado en el diario, pero como principal asertado — ver A-5 |
| Carrera entre dos ciclos sobre una misma cadena | quizá silencia un escritor | **FALSADO** | `_check_continuation` + `SegmentedChain.check` + lock/transacción lo rechazan (`service/case_store.py:34-62`, `service/chain_store.py:156-201`) |

---

## Lectura de conjunto

La afirmación central —**el objeto que determina el veredicto es inalcanzable
desde cualquier camino controlado por el agente**— **se sostiene**. Tres intentos
directos de moverlo quedaron falsados. El scorer determinista, el sello de la
window y la cadena de entradas hacen lo que dicen.

Lo que no se sostiene es el anillo que rodea a ese objeto:

- **el sello no ata el veredicto a la máquina** (A-1) — la identidad forense es una
  etiqueta mutable que ni el servicio ni el verificador independiente comparan;
- **la autorización cubre un camino de cinco** (A-3) y no cubre al delegante (A-9);
- **la escalación obligatoria del motor depende de un estado que el agente fija**
  (A-2) — el efecto de una herramienta que el comandante no tiene, alcanzado
  ordenando dos que sí tiene;
- **ABSTAIN no tiene salida hacia un humano** (A-4) y se convierte en `benign` al
  mostrarse (A-6);
- **la identidad autenticada y la registrada divergen**, y la credencial válida es
  el único input que se penaliza (A-5);
- **lo tamper-evident es el diario, no el estado operativo** (A-8).

El patrón es consistente y vale más que cualquier hallazgo suelto: **cada defensa
es correcta dentro de su módulo y no se aplica en la composición.** El catálogo
autoriza taskings pero no endpoints. El sello cubre el veredicto pero no la
identidad. El diario está encadenado pero el estado no. La red de seguridad del
motor está condicionada al mismo estado que el agente escribe. El id estable
existe pero la ruta lo tipa como entero. Ninguno de estos es un fallo de
implementación: son fracturas en la junta entre dos piezas correctas.

---

## Estado de remediación

Cada fix se escribió con su test **rojo primero**, contra el árbol vulnerable, y
está fijado en `tests/test_redteam_round2_fixes.py` (29 pruebas, con sus
controles negativos). Los scripts de `repro/` que reimplementaban lógica ahora
llaman al código real, así que son testigos del árbol vivo, no fotos del viejo.

| ID | Estado | Commit | Qué cambió |
|----|--------|--------|------------|
| A-1 | **Cerrado** | `8cf1821` | La entrada v2 sella `host_hash`; `verify_stream(case_id=, host=)` y `verify_bundle` comprueban la identidad reclamada contra los sellos. El exhibit reetiquetado ahora da `FAIL` (exit 1) nombrando ambas sustituciones. |
| A-2 | **Cerrado** | `0db51d1` | `escalation_covers_verdict` + `raise_unescalated_malice`: la garantía es por `entry_hash`, no por "¿hay alguna escalación abierta?". Los dos órdenes de llamada disparan. |
| A-3 | **Cerrado** | `808e65f` | `_authorize` en el borde HTTP de las cuatro rutas que alcanzan el núcleo sellado; `authorize_fleet` para los seis contratos del dispatch. |
| A-9 | **Cerrado** | `808e65f` | `run_cycle` autoriza al comandante antes del chequeo de vencimiento: un departamento no publicado no llega ni a la memoria del caso. |
| A-5 | **Cerrado (parcial, ver abajo)** | `1d17d3b` | Eliminada la inversión: una identidad verificada fuera del roster queda como asertada, no rechazada. El departamento reclamado se valida contra el catálogo. `default_department()` es una postura declarada y visible en `/health`. |
| A-4 | **Cerrado** | `eb7029b` | `is_unresolved` (ligado al hueco ABIERTO, no a `worst_verdict`), techo de 12 h, `stand_down` rechazado, y `raise_unresolved_abstain` tras 3 ciclos sin concluir. |
| A-6 | **Parcial, por decisión** | `eb7029b` | Ver abajo. |
| A-7 | **Cerrado** | `989abac` | La ruta acepta el id estable; `_trim` cede por severidad (`_escalation_rank`) antes que por antigüedad. |
| A-8 | **Cerrado como evidencia** | `989abac` | `_journal_backing`: todo estado operativo debe rastrearse a la mutación sellada que lo produjo. Es tamper-**evidencia**, no tamper-prevención. |

### A-6 — no aplicado del todo, y por qué

La transición `ABSTAIN → status "benign"` está fijada **a propósito** por dos
pruebas en `tests/test_case_store.py`: un ABSTAIN es un hecho sobre una
*recolección*, no sobre el host, y una recolección posterior completa puede
superarlo. Prohibir la transición cambiaba un estado absorbente por otro —
todo caso que alguna vez abstuvo quedaría etiquetado así para siempre. No
sobrescribí ese diseño.

Lo que sí se cerró:
- la divergencia ya no es silenciosa — la fila de la cola lleva
  `supersedes_unresolved` cuando `status` y `worst_verdict` discrepan;
- la consecuencia peligrosa está cerrada por A-4: mientras el hueco siga
  abierto el planner no puede aparcar ni cerrar el caso, diga lo que diga
  `status`.

Lo que **sigue abierto**, registrado en vez de disimulado: la transición se
dispara con *cualquier* veredicto concluyente posterior, incluido uno de una
superficie distinta de la que el ABSTAIN declaró faltante. `ABSTAIN_INSUFFICIENT`
pide "correlacionar procesos con su actividad de red en una ventana"; un
veredicto limpio sobre la superficie de persistencia no responde a eso.
Cerrarlo exige que el store sepa qué recolección responde a qué hueco —
información que hoy no tiene, porque solo ve estados de veredicto.

### Otros items abiertos

| Item | Origen | Por qué sigue abierto |
|------|--------|------------------------|
| El default de un llamante anónimo es `incident-response`, el departamento con acceso a los 9 agentes | A-5 | Cambiarlo rompe el ciclo autónomo del demo público. Ahora es explícito (`VIGIA_DEFAULT_DEPARTMENT`), visible en `/health` y rechazado si no nombra un departamento publicado — pero sigue siendo la postura por defecto. Es una decisión de producto. |
| Reconocer una escalación no exige credencial | A-7 | `_principal_for` sin `claimed` resuelve al default asertado, y el `actor` registrado es el `examiner_id` que el llamante escribe. Reconocer es lo que hace que un veredicto malicioso deje de pedir atención. El registro dice `acknowledged_by_authenticated: False`, así que es honesto, no oculto — pero exigir identidad verificada aquí es la misma decisión de producto que la fila anterior. |
| Las entradas v1 no pueden atarse a un host | A-1 | No hay forma de sellar retroactivamente. Los verificadores lo dicen como WARN nombrando exactamente qué quedó fuera de alcance, nunca como PASS silencioso. |

## Recomendaciones (fuera del alcance de este cambio — solo registro)

1. **A-1:** incluir `host` (y el `case_id` de la window) en el payload sellado de
   la entrada, o hacer que `verify_entries` compare `entry["case_id"]` /
   `window["case_id"]` / `window["host"]` con el sobre y falle si divergen. Un
   `PASS` no debería ser posible sobre un exhibit cuya cabecera contradice sus
   sellos.
2. **A-2:** condicionar la red del motor a *"¿existe ya una escalación abierta cuya
   `sealed_basis` incluya este `entry_hash`?"* en vez de *"¿existe alguna
   escalación abierta?"*.
3. **A-3:** llamar a `catalog.authorize` en el borde HTTP de todo endpoint que
   alcance `session.adjudicate()`, con el departamento del principal resuelto.
4. **A-4/A-6:** dar a `ABSTAIN` una salida: techo de intervalo, escalación tras N
   ciclos sin concluir, e incluir `ABSTAIN_*` en la guarda de `stand_down`. No
   dejar que `_update_open_question` sobrescriba `status` cuando `worst_verdict`
   sigue siendo `ABSTAIN_*`; y no resolver una pregunta abierta con una conclusión
   de otra superficie.
5. **A-5:** una identidad verificada fuera del roster debería degradar al camino
   asertado (o rechazar **todo**), nunca ser el único caso rechazado. Validar
   `claimed_department` contra `catalog.DEPARTMENTS` en `resolve`. Y que el
   default de un llamante anónimo no sea el departamento más privilegiado.
6. **A-7:** tipar el path param como `str` para que la rama de id estable sea
   alcanzable; ordenar el desalojo de `_trim` por `_escalation_rank` antes que por
   antigüedad; y no desalojar nunca una escalación no reconocida con base
   `MALICE`.
7. **A-8:** o bien sellar el estado operativo (un hash del resumen dentro de la
   entrada de diario), o bien reducir la afirmación del docstring a lo que la
   función prueba: que el diario es íntegro, no que el estado coincide con él.
