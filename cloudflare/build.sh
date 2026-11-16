#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
npm --prefix mcp ci --ignore-scripts
npm --prefix frontend ci --ignore-scripts
npm --prefix frontend run build
node scripts/catalogue/stage-media.mjs frontend/dist
