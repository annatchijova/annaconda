#!/usr/bin/env bash
# Re-render visual/architecture.png from the live /architecture page.
#
# The diagram is the README's headline image, and it used to be a hand-taken
# screenshot with no recipe: nobody could reproduce its framing, and a layout
# fix in the page could not be carried into the asset without guessing. It also
# meant a defect could sit in the image while the page was already correct --
# which is exactly what happened: the PNG read "isjoint tool contracts" because
# a badge overlapped the caption at the width it was captured at.
#
# Two settings are not obvious and are the whole reason this file exists:
#
#   --window-size=1500,1900 --force-device-scale-factor=2
#       reproduces the original 3000x3800 exactly, so the replacement drops in
#       without reflowing anything that embeds it.
#
#   --force-prefers-reduced-motion
#       the page fades its sections in (`.fade { opacity: 0; animation: rise }`)
#       and headless captures before they finish, so most of the diagram comes
#       out invisible and the agent band comes out EMPTY. The page already
#       honours prefers-reduced-motion by skipping the animation, so this asks
#       for the final state through its own accessibility branch rather than
#       hacking the CSS or guessing at a sleep.
#
# The service must be running. Pass a URL to point somewhere else:
#   scripts/render_architecture.sh http://127.0.0.1:8137/architecture
set -euo pipefail

URL="${1:-http://127.0.0.1:8080/architecture}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/visual/architecture.png"

find_chrome() {
    for c in \
        "${CHROME:-}" \
        "/c/Program Files/Google/Chrome/Application/chrome.exe" \
        "/c/Program Files (x86)/Google/Chrome/Application/chrome.exe" \
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
        google-chrome google-chrome-stable chromium chromium-browser
    do
        [ -z "$c" ] && continue
        if [ -x "$c" ]; then echo "$c"; return 0; fi
        if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
    done
    return 1
}

CHROME_BIN="$(find_chrome)" || {
    echo "No Chrome or Chromium found. Set CHROME=/path/to/chrome and retry." >&2
    exit 1
}

if ! curl -fsS -o /dev/null --max-time 10 "$URL"; then
    echo "Cannot reach ${URL} -- start the service first:" >&2
    echo "    uvicorn service.app:app --port 8080" >&2
    exit 1
fi

TMP_PROFILE="$(mktemp -d)"
trap 'rm -rf "$TMP_PROFILE"' EXIT

echo "==> Rendering ${URL}"
"$CHROME_BIN" \
    --headless=new --disable-gpu --hide-scrollbars \
    --user-data-dir="$TMP_PROFILE" \
    --force-prefers-reduced-motion \
    --virtual-time-budget=8000 \
    --force-device-scale-factor=2 \
    --window-size=1500,1900 \
    --screenshot="$OUT" \
    "$URL" >/dev/null 2>&1

[ -s "$OUT" ] || { echo "==> FAIL: no image written" >&2; exit 1; }

echo "==> Wrote ${OUT}"

# Pick an interpreter that actually RUNS. `command -v python` succeeds on
# Windows even when it resolves to the Microsoft Store stub, which answers
# "Python was not found" and exits non-zero -- see INSTALL.md.
PY=""
for cand in python3 python py; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "" >/dev/null 2>&1; then
        PY="$cand"; break
    fi
done

if [ -n "$PY" ]; then
    "$PY" - "$OUT" <<'EOF' || true
import sys, struct
# PNG header: width and height are big-endian uint32 at bytes 16..24.
with open(sys.argv[1], "rb") as fh:
    w, h = struct.unpack(">II", fh.read(24)[16:24])
print(f"==> {w}x{h} (expected 3000x3800)")
if (w, h) != (3000, 3800):
    print("==> WARNING: dimensions differ from the committed asset", file=sys.stderr)
EOF
fi
