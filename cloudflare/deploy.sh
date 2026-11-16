#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
npm ci --ignore-scripts
bash build.sh
npx wrangler whoami
npx wrangler deploy
