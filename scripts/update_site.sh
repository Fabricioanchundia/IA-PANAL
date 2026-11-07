#!/usr/bin/env bash
# Refresh the public dashboard data: fetch logs, enrich, analyze, detect, publish.
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/fetch_logs.sh
uv run python -m panal.ingest
uv run python -m panal.enrich
if curl -fs --max-time 3 http://localhost:11434/api/tags >/dev/null; then
  uv run python -m panal.analyst --limit 200
else
  echo "Ollama is not running: skipping AI analysis (sessions will show rule-based verdicts)."
fi
uv run python -m panal.sigma >/dev/null
uv run python -m panal.publish
echo
echo "Done. Preview: (cd site && python3 -m http.server 8000) then open http://localhost:8000"
