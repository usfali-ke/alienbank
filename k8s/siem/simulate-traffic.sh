#!/usr/bin/env bash
# Generate a realistic mix of AlienBank activity so the SIEM has security events
# to browse: normal logins + data access, plus attack patterns (brute force,
# credential spraying, IDOR/BOLA cross-tenant access). All traffic goes through
# the ingress, so it exercises the same path a real user/attacker would.
set -euo pipefail

HOST="${ALIENBANK_HOST_HEADER:-alienbank.localtest.me}"
BASE="${ALIENBANK_BASE_URL:-http://localhost}"
CURL=(curl -s -o /dev/null -H "Host: ${HOST}")
JAR="$(mktemp -d)/cookies"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

login() { # username password  -> stores session cookie in $JAR
  "${CURL[@]}" -c "$JAR" -b "$JAR" -X POST \
    --data-urlencode "username=$1" --data-urlencode "password=$2" \
    -w "  login %{http_code}  ($1)\n" -o /dev/null "$BASE/login" || true
}

get() { # path
  "${CURL[@]}" -b "$JAR" -w "  GET  %{http_code}  $1\n" "$BASE$1" || true
}

# ---------------------------------------------------------------------------
say "1. Normal customer sessions (login + browse own data)"
for u in ana:ana123 duncan:duncan123 brenda:brenda123 fatima:fatima123; do
  login "${u%%:*}" "${u##*:}"
  get "/api/accounts"
  get "/api/recent-recipients"
  get "/api/loans/limit"
done

say "2. Own-account statement reads (data_access, success)"
login ana ana123
get "/api/accounts/0101700002/statement"
get "/api/accounts/0101700001/balance"

say "3. IDOR / BOLA — ana tries to read OTHER customers' accounts (blocked / cross_tenant)"
# ana (owns 01017000xx) reaches for duncan's and fatima's accounts:
get "/api/accounts/0202700011/statement"
get "/api/accounts/0505700040/balance"
get "/api/accounts/0303700020/statement"

say "4. Brute force — many failed passwords against ONE account (single target_ref)"
for i in $(seq 1 8); do
  "${CURL[@]}" -X POST --data-urlencode "username=ana" \
    --data-urlencode "password=guess$i" -w "  brute %{http_code}\n" "$BASE/login" || true
done

say "5. Credential spraying — one source, MANY accounts, one common password"
for u in ana duncan brenda kevin fatima teller mary nonexistent; do
  "${CURL[@]}" -X POST --data-urlencode "username=$u" \
    --data-urlencode "password=Password123" -w "  spray %{http_code}  ($u)\n" "$BASE/login" || true
done

say "6. Privilege probing — customer hits a teller-only endpoint"
login kevin kevin123
get "/api/teller/customer/ana/accounts"

say "Done. Traffic sent. Allow ~10s for fluentd to flush to OpenSearch."
