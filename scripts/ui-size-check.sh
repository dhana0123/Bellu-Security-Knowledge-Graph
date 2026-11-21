#!/usr/bin/env bash
# Fails if the total gzipped JavaScript in ui/dist/assets exceeds 300 KB.
# The current build is about 230 KB (React, React Router, Cytoscape); 300 KB leaves
# about 30% headroom, so an accidental large dependency fails CI but normal growth does not.
# Override with UI_JS_GZIP_LIMIT_KB. Set NODE=bun to run on a host without Node.
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${NODE:-node}" scripts/ui-size-check.mjs "${UI_JS_GZIP_LIMIT_KB:-300}"
