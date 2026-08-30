# YARA collection: detecting malware without deciding with it

How signature-based detection enters annaconda, how to prove it works on a real
Windows host without a malware sample, and — the part that matters most — what
it deliberately does *not* do.

## The short version

Velociraptor already knows how to match YARA rules against process memory and
files. annaconda **collects and seals those matches**; it does not reimplement a
scanner, and it does not let a match move a verdict. A hit is sealed inside the
evidence window, covered by `window_hash`, exported through STIX/CACAO — and the
verdict comes out exactly as it would have without the hit.

That last clause is a design decision, not an unfinished feature. See
[The open decision](#the-open-decision).

## How it works

Two curated templates in `tools/velociraptor/vql_templates.py`:

| Template | Collects | MITRE-adjacent |
|---|---|---|
| `yara_process` | YARA matches in **process memory** (needs Administrator) | in-memory-only payloads |
| `yara_file` | YARA matches in **files** under a target glob | staged tooling on disk |

Both produce artifacts of evidence type `malware_static_analysis`, carry the
process id when the row has one, and go through the same normalize → freeze →
seal path as every other collection. They appear automatically in `GET /hunts`.

### Rules are named, never supplied

`RuleSet` names a file committed under `tools/velociraptor/yara_rules/`. Rule
**text** is refused at the boundary:

- the parameter pattern (`[A-Za-z0-9_-]{1,64}`) cannot express a path separator,
  so traversal is not representable;
- the resolved path is re-checked against the rules directory after resolution;
- a ruleset that is not committed **fails loud**, rather than scanning with no
  rules and reporting a clean host it never examined.

This is the curated-template contract applied to a new kind of input. A YARA rule
is executable matching logic, so accepting one from a caller would be exactly the
free-form instruction reaching the evidence source that the registry exists to
prevent — and an expensive rule is a denial of service against the endpoint under
investigation.

The agent chooses *which* hunts to run. The ruleset and the scan target are
vetted in `agent/tools.py::_DEFAULT_PARAMS`, never filled by the model. The
default file target is the staging directory (`…/AppData/Local/Temp/**`) rather
than all of `C:/Users`, because the scan is paid for on the endpoint being
investigated: the narrow scope is the default and widening it is deliberate.

## Proving it works, without malware

You do not need a lab, a sample, or EICAR. The committed baseline ruleset carries
a harmless marker string for exactly this.

### 1. File scan — two minutes, no privileges

```powershell
"ANNACONDA-PURPLE-TEAM-YARA-SELFTEST" | Out-File $HOME\Desktop\selftest.txt

python scripts_lib\windows_live_collect.py C:\path\velociraptor.exe `
    --templates yara_file --yara-glob "C:/Users/<user>/Desktop/**" --show-fields
```

Expect one `annaconda_purple_team_marker` hit, sealed into the window.

### 2. Process memory — the interesting one, needs Administrator

```powershell
# leave this running in another console:
$m = "ANNACONDA-PURPLE-TEAM-YARA-SELFTEST"; Read-Host "enter to exit"
```

then collect with `--templates yara_process`. This is real YARA against the live
memory of a real process; the only difference from an implant hunt is that what
it finds is a string you put there.

### Why not EICAR?

EICAR works because antivirus products ship a signature for it. annaconda matches
*our* committed rules, so EICAR would only hit if we wrote a rule for it — making
it no more real than the marker, only more famous. It is also deleted on sight by
Defender, so the file tends to vanish before the scan runs.

## Things that will bite you

**Encoding.** The marker is declared `ascii wide` on purpose. Windows holds
strings in memory as UTF-16, and Windows PowerShell 5.1's `Out-File` writes
UTF-16LE by default; an ascii-only rule misses both, and the miss reads as a
broken pipeline rather than a rule that did not match.
(`tests/test_yara_collection.py` pins the encoding.)

**Self-match.** Scanning a directory that contains the repository will match
`credential_dumper_strings` against the `.yar` file itself, because that file
contains the strings it searches for. It is the classic YARA false positive, and
a standing reminder of why a match is an indicator and not a conclusion.

**Rows with no scan time are dropped.** `normalize_rows` requires a non-empty
string in the template's `timestamp_field`, so the VQL must project `ScanTime`.
Dropped rows are counted in the normalization report — never silently discarded,
and never counted as a scan that found nothing.

**The VQL is the least verified part of this.** The `proc_yara()` / `yara()`
argument names and the shape of a hit row are what the first Windows run is meant
to establish. Use `--show-fields`, and correct the query with `--vql-map` (a JSON
`{artifact: vql}`) rather than editing Python.

## The open decision

A collected hit carries the adapter's no-signal floor (`raw_score = 1/20`), so it
does not influence the verdict. `tests/test_yara_collection.py::
test_a_yara_hit_does_not_move_the_verdict` pins that equality, and the test was
verified as a real oracle rather than a vacuous one: weighting the same hit at
9/10 moves the verdict `NOISE → SUSPICION`, so the test can fail.

Whether a signature match *should* weigh on a sealed verdict is genuinely open,
and the reason is not caution for its own sake:

- **The adversary chooses the bytes being matched.** A rule hit is a statement
  about content the attacker authored. That is the same trust problem the whole
  system is built around, and it is why enrichment (VirusTotal, MISP) is sealed
  *beside* the evidence and never fed to the scorer.
- **A miss means nothing.** No hit is not evidence of a clean host; it is
  evidence that these rules did not match. Giving hits weight without giving
  misses meaning produces an asymmetry that has to be stated, not assumed.
- **Signatures and structural fractures are different kinds of claim.** CAIE's
  fractures assert impossibilities ("the beacon predates its own process"). A
  signature asserts a resemblance. Fusing them into one score requires saying
  what the resemblance is worth.

Until that is answered deliberately, the test is what stops it from being
answered by accident.

## Still missing

- **The VQL, validated on Windows.** Blocked only on a machine.
- **A fleet role that runs these hunts.** The templates are reachable through
  `GET /hunts` and the investigator, but no specialist in `agent/fleet.py`
  collects them yet, so an unattended cycle will never run a YARA scan.
- **The scoring decision above.**
- **`injection_technique` from real telemetry.** Unbacked executable memory is
  how EDRs actually detect hollowing, and Velociraptor can see it — but Chrome,
  .NET and PowerShell all have unbacked executable memory constantly (JIT), so a
  naive mapping fabricates `PROCESS_INJECTION_ANTIFORENSIC` at severity 0.85 on
  any machine with a browser open. Same false-positive class as the temporal rule
  before it required a PID link.
