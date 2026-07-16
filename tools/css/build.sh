#!/usr/bin/env bash
# Regenerate the static, purged Tailwind stylesheet that replaced the
# browser-runtime "Play CDN" compiler (which was dev-only, shipped a 398 KB
# JS blob, compiled CSS client-side on every page load, and couldn't emit
# some base-surface utilities — which is why dark mode was stuck).
#
# No npm / node_modules: uses the standalone Tailwind CLI binary. Run this
# whenever markup changes add new utility classes, then commit the emitted
# crates/vortex-cli/static/tailwind.css (a vendored static asset, like the
# other files under static/). CI can run it to guard against drift.
#
# Usage:  tools/css/build.sh
set -euo pipefail
cd "$(dirname "$0")"

TW_VERSION="v3.4.17"   # keep in sync with the classes the app was built against
BIN="./tailwindcss"
OUT="../../crates/vortex-cli/static/tailwind.css"

if [ ! -x "$BIN" ]; then
  echo ">>> fetching standalone Tailwind CLI $TW_VERSION (no npm) ..."
  curl -fsSL -o "$BIN" \
    "https://github.com/tailwindlabs/tailwindcss/releases/download/$TW_VERSION/tailwindcss-linux-x64"
  chmod +x "$BIN"
fi

echo ">>> building $OUT ..."
"$BIN" -c tailwind.config.js -i input.css -o "$OUT" --minify

echo ">>> done: $(du -h "$OUT" | cut -f1) $OUT"
