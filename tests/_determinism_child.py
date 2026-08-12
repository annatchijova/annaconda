"""Child process for the determinism test.

Reads a case JSON from argv[1], scores it with vigia_scorer._vigia_score,
and prints one line: ``<sha256-of-canonical-result-json> <verdict>``.

Run in a fresh interpreter per invocation so that no in-process state
(dict ordering, caches, PYTHONHASHSEED) can leak between runs.
"""

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from vigia_scorer import _vigia_score  # noqa: E402


def main() -> None:
    case = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    result = _vigia_score(case)
    canonical = json.dumps(
        result, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    print(f"{digest} {result.get('verdict', 'MISSING')}")


if __name__ == "__main__":
    main()
