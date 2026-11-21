#!/usr/bin/env bash
# Fails if a production dependency of ui/ is not MIT, BSD-2-Clause, BSD-3-Clause, ISC,
# Apache-2.0, MPL-2.0, 0BSD, CC0-1.0, or (argparse only) Python-2.0.
# Needs ui/node_modules (npm ci). Set NODE=bun to run on a host without Node.
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${NODE:-node}" scripts/ui-license-check.mjs
