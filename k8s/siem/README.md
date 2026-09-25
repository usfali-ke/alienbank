# AlienBank SIEM — dashboards & detection

The SIEM stack (OpenSearch + Dashboards + fluentd) ingests AlienBank's PII-free
security events. This dir also provisions the **dashboard** and the **alerting
monitors** (the Sigma rules from `SECURITY_LOGGING_PLAN.md §3.5`).

## Files

| File | Purpose |
|------|---------|
| `opensearch.yaml` | OpenSearch + Dashboards + ingress (`siem.localtest.me`) |
| `fluentd.yaml` | fluentd DaemonSet: tail → parse security JSON → OpenSearch |
| `simulate-traffic.sh` | Generate normal + attack traffic (brute force, spray, IDOR/BOLA, priv-esc) |
| `build_dashboards.py` | Generate the Dashboards saved-objects NDJSON |
| `dashboards-objects.ndjson` | Generated: index-pattern + 10 viz + 1 dashboard |
| `build_monitors.py` | Generate the alerting monitors JSON (8 rules) |
| `load_monitors.sh` | Idempotently load monitors into OpenSearch alerting |
| `monitors.json` | Generated monitor bodies |

## Provision (one time)

```bash
# 1. Index patterns are created by the deploy step; if missing:
python3 build_dashboards.py > dashboards-objects.ndjson
curl -s -X POST 'http://siem.localtest.me/api/saved_objects/_import?overwrite=true' \
  -H 'osd-xsrf: true' --form file=@dashboards-objects.ndjson

# 2. Alerting monitors
./load_monitors.sh
```

## See it work

```bash
../../k8s/siem/simulate-traffic.sh   # or: ./simulate-traffic.sh from repo root path
sleep 12                             # let fluentd flush
```

Then open **http://siem.localtest.me/** → **Dashboard → "AlienBank — Security
Overview"** (auto-refreshes every 10s, last-24h window).

## Dashboard panels

- **Blocked (IDOR/BOLA/priv) — 24h** — single big-count KPI (`metric` viz).
  The count is not itself clickable (OSD 2.13 metric has no drilldown), so a
  **"🔍 View the blocked events →"** link sits directly beneath it and opens
  Discover pre-filtered to those exact events.
- **Critical events — 24h** — same: big count + a "View the critical events →"
  drill-down link beneath it.
- **Outcome breakdown** — success / failure / blocked donut
- **Auth outcomes over time** — stacked bars by outcome (authentication only)
- **Event severity over time** — stacked bars by severity
- **Action breakdown** — donut over `event.action`
- **Top actors (`actor.ref`)** — table (pseudonyms, never usernames)
- **Top source IPs** — table

### Downloading

- Any panel: **panel menu (⋮) → Inspect → Download CSV** exports that panel's
  underlying data.
- Whole dashboard: the top-bar **Reporting** menu exports PNG/PDF.
- The drill-down **View events** links land in Discover, where **Share →
  Reporting → Download CSV** exports the full filtered event list (the 32 / 10).

## Alerting monitors (Sigma rules)

Run on `alienbank-security-*`, 1-min schedule, 10-min rolling window.
Severity 1 = highest.

| Monitor | Type | Trigger | Sev |
|---------|------|---------|-----|
| Brute force (single account) | bucket | ≥5 login failures sharing one `target_ref` | 2 |
| Credential spraying | bucket | one `source.ip` failing against ≥5 distinct `target_ref` | 2 |
| Auth throttle tripped | query | any `action=login_throttle` | 1 |
| IDOR/BOLA probing | query | `cross_tenant=true` OR blocked `data_access` | 2 |
| Guardrail evasion | query | `attack=true` with `bypassed_layers` present | 2 |
| Agent compromise | query | `agent_turn` `outcome=compromise` | 1 |
| Prompt/canary leak | query | `canary_leak=true` | 1 |
| Privilege escalation | query | non-teller blocked on teller endpoint | 2 |

The last four need **chat-agent** attacks (levels 1–3) to fire; the HTTP
`simulate-traffic.sh` exercises the first four + throttle + IDOR + priv-esc.

To add notifications (Slack/email/webhook), attach a channel to each monitor's
trigger `actions` in the Dashboards **Alerting** UI, or extend `build_monitors.py`.

## Verifying monitors fire

```bash
# dry-run every monitor against the current window and print FIRED/quiet
NS=siem; API=http://localhost:9200/_plugins/_alerting/monitors
kubectl -n $NS exec -i deploy/opensearch -- curl -s "$API/_search" \
  -H 'Content-Type: application/json' -d '{"size":50,"query":{"match_all":{}}}' </dev/null \
 | python3 -c "import sys,json;[print(h['_id'],'::',h['_source']['name']) for h in json.load(sys.stdin)['hits']['hits']]"
# then POST $API/<id>/_execute?dryrun=true for each id
```
