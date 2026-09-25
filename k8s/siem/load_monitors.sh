#!/usr/bin/env bash
# Load the AlienBank alerting monitors into OpenSearch (idempotent).
# Runs build_monitors.py, then for each monitor deletes any existing one with
# the same name and creates it fresh. Executes curl *inside* the opensearch pod
# so it works regardless of host networking.
set -euo pipefail
cd "$(dirname "$0")"

NS=siem
OS="kubectl -n $NS exec -i deploy/opensearch -- curl -s"
API="http://localhost:9200/_plugins/_alerting/monitors"

python3 build_monitors.py > monitors.json

count=$(python3 -c "import json;print(len(json.load(open('monitors.json'))))")
echo "loading $count monitors…"

for i in $(seq 0 $((count-1))); do
  body=$(python3 -c "import json;print(json.dumps(json.load(open('monitors.json'))[$i]))")
  name=$(python3 -c "import json;print(json.load(open('monitors.json'))[$i]['name'])")

  # Delete existing monitor(s) with this name.
  existing=$($OS -H 'Content-Type: application/json' "$API/_search" -d "{
    \"query\": {\"match_phrase\": {\"monitor.name.keyword\": \"$name\"}}
  }" 2>/dev/null | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    for h in d.get('hits',{}).get('hits',[]): print(h['_id'])
except Exception: pass" || true)
  for id in $existing; do
    $OS -X DELETE "$API/$id" >/dev/null 2>&1 || true
  done

  # Create.
  resp=$($OS -X POST -H 'Content-Type: application/json' "$API" -d "$body" 2>/dev/null)
  ok=$(printf '%s' "$resp" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin); print('OK' if d.get('_id') else 'ERR '+json.dumps(d)[:200])
except Exception as e: print('ERR parse')" )
  printf '  [%s] %s\n' "$ok" "$name"
done

echo "done."
