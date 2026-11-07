#!/usr/bin/env bash
# Download this month's free DB-IP City Lite database (CC BY 4.0, no account needed).
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p data/geo
month="$(date +%Y-%m)"
curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-${month}.mmdb.gz" \
  | gunzip > data/geo/dbip-city-lite.mmdb.tmp
mv data/geo/dbip-city-lite.mmdb.tmp data/geo/dbip-city-lite.mmdb
ls -lh data/geo/dbip-city-lite.mmdb
