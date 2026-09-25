// G3 performance_within_slo: p95 latency of the unauthenticated entry page
// and an authenticated API read, against the G2 image. The gate compares
// http_req_duration p(95) with the SLO; thresholds here only make k6's own
// output readable.
import http from "k6/http";
import { check } from "k6";

const BASE = (__ENV.TARGET_URL || "http://127.0.0.1:8080").replace(/\/$/, "");

export const options = {
  vus: 10,
  duration: "30s",
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "max"],
};

export function setup() {
  const res = http.post(`${BASE}/login`, { username: "ana", password: "ana123" }, { redirects: 0 });
  const cookie = res.cookies.alienbank_session && res.cookies.alienbank_session[0];
  return { session: cookie ? cookie.value : "" };
}

export default function (data) {
  check(http.get(`${BASE}/login`), { "login page 200": (r) => r.status === 200 });
  const me = http.get(`${BASE}/api/accounts`, { cookies: { alienbank_session: data.session } });
  check(me, { "accounts 200": (r) => r.status === 200 });
}

// Machine-readable summary for the gate (SUMMARY_OUT), plus a one-line
// human summary — no remote jslib import, so the run needs no internet.
export function handleSummary(data) {
  const d = data.metrics.http_req_duration.values;
  const failed = data.metrics.http_req_failed ? data.metrics.http_req_failed.values.rate : null;
  const checks = data.metrics.checks ? data.metrics.checks.values.rate : null;
  const line = `http_req_duration p(95)=${d["p(95)"]}ms avg=${d.avg}ms; http_req_failed=${failed}; checks=${checks}\n`;
  return { [__ENV.SUMMARY_OUT || "k6-summary.json"]: JSON.stringify(data), stdout: line };
}
