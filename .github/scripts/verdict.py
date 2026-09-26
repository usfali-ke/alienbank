"""One verdict per control.

Reads a tool's report, applies the gate threshold, writes
`result=<json>` ({status, detail, metrics}) to $GITHUB_OUTPUT for the gate
job, and exits 1 on fail so the control's own job goes red:

    python3 .github/scripts/verdict.py <check> [args...]

A report that is missing or unreadable is a fail — a scanner that didn't
run is not a clean scan. Tools are always run with "don't fail on
findings" (--exit-code 0, || true): their exit codes mean different things
(findings vs. crashed), so this script is the one place a threshold is
decided. Settings come from env, never from ${{ }} inside a script.
"""

import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

env = os.environ.get


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def missing(tool):
    return False, f"{tool} did not produce a report", None


# --- G1 ---------------------------------------------------------------------


def reviewers(path):
    """Latest review per reviewer, author excluded; only approvals of the
    current head count — an approval of an older revision didn't review
    what's actually being merged."""
    author, head, required = env("AUTHOR"), env("HEAD_SHA"), int(env("REQUIRED_APPROVALS", "1"))
    latest = {}
    with open(path) as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                if r["user"]["login"] != author and r["state"] not in ("COMMENTED", "PENDING"):
                    latest[r["user"]["login"]] = r
    approvals = sorted(u for u, r in latest.items() if r["state"] == "APPROVED" and r["commit_id"] == head)
    blocking = sorted(u for u, r in latest.items() if r["state"] == "CHANGES_REQUESTED")
    detail = f"{len(approvals)} of {required} required approval(s) on head {head[:7]} (author {author} excluded)"
    if blocking:
        detail += f"; changes requested by {', '.join(blocking)}"
    return len(approvals) >= required and not blocking, detail, {"approvals": len(approvals), "required": required}


def tests(pattern):
    """JUnit files → passed/total. A skipped test is excluded from the
    total, and zero tests is a fail, so skipping everything can't pass.
    RC is the test command's exit code (also catches collection errors)."""
    passed = total = 0
    for path in glob.glob(pattern, recursive=True):
        for case in ET.parse(path).getroot().iter("testcase"):
            tags = {child.tag for child in case}
            if "skipped" in tags:
                continue
            total += 1
            passed += not tags & {"failure", "error"}
    ok = env("RC") == "0" and total > 0 and passed == total
    return ok, f"{passed}/{total} passed ({env('LABEL', pattern)})", {"tests_passed": passed, "tests_total": total}


def semgrep(path):
    report = load(path)
    if report is None:
        return missing("semgrep")
    results = report.get("results", [])
    blocking = [r for r in results if r["extra"].get("severity") == "ERROR"]  # semgrep's High/Critical tier
    rules = ", ".join(sorted({r["check_id"].rsplit(".", 1)[-1] for r in blocking})[:6])
    return not blocking, f"{len(blocking)} Critical/High of {len(results)} findings (semgrep p/default + p/python){': ' + rules if rules else ''}", None


def gitleaks(path):
    report = load(path)
    if report is None:
        return missing("gitleaks")
    return not report, f"{len(report or [])} leak(s) in {env('RANGE')} (gitleaks)", None


def commits(path):
    """commits.tsv: short sha, GitHub's verified flag, reason."""
    with open(path) as f:
        rows = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    unsigned = [f"{sha} ({reason})" for sha, verified, reason in rows if verified != "true"]
    detail = f"{len(unsigned)} of {len(rows)} commit(s) unsigned/unverified" + (f": {', '.join(unsigned[:6])}" if unsigned else "")
    return rows and not unsigned, detail, None


# --- G2 ---------------------------------------------------------------------


def build(dockerfile):
    """Config controlled (every base ref digest-pinned) and reproducible
    (cached build == --no-cache build == pushed image, env D1/D2/PUSHED)."""
    refs, bad = [], []
    with open(dockerfile) as f:
        for line in f:
            m = re.match(r"\s*#\s*syntax=(\S+)", line) or re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)", line, re.I)
            if m:
                refs.append(m.group(1))
                if not re.search(r"@sha256:[0-9a-f]{64}$", m.group(1)):
                    bad.append(m.group(1))
    pins = f"{len(refs) - len(bad)}/{len(refs)} base refs digest-pinned" + (f" (unpinned: {', '.join(bad)})" if bad else "")

    d1, d2, pushed = env("D1"), env("D2"), env("PUSHED")
    short = lambda d: (d or "none")[:19]  # noqa: E731
    if env("RC") != "0" or not d1 or not d2:
        ok, repro = False, "build failed"
    elif d1 != d2:
        ok, repro = False, f"NOT reproducible: {short(d1)} vs {short(d2)} (cached vs --no-cache)"
    elif pushed != d1:
        ok, repro = False, f"reproducible ({short(d1)}) but pushed digest differs ({short(pushed)})"
    else:
        ok, repro = True, f"2 builds (cached + --no-cache, same runner) and the pushed image all {short(d1)}"
    return ok and refs and not bad, f"{repro}; {pins}; Dockerfile + uv.lock at {env('GITHUB_SHA', '')[:7]}", None


def trivy(path):
    """Critical/High with a released fix block; ones with no upstream fix
    are reported but don't block (BLOCK_UNFIXED=true to block them too)."""
    report = load(path)
    if report is None:
        return missing("trivy")
    vulns = [v for r in report.get("Results") or [] for v in r.get("Vulnerabilities") or []]
    block_unfixed = env("BLOCK_UNFIXED") == "true"
    blocking = vulns if block_unfixed else [v for v in vulns if v.get("FixedVersion")]
    unfixed = [v for v in vulns if not v.get("FixedVersion")]
    by_sev = {}
    for v in blocking:
        by_sev[v["Severity"]] = by_sev.get(v["Severity"], 0) + 1
    sev = ", ".join(f"{k} {n}" for k, n in sorted(by_sev.items())) or "none"
    top = ", ".join(sorted({f"{v['VulnerabilityID']} ({v['PkgName']})" for v in blocking})[:8])
    detail = (f"{len(blocking)} blocking Critical/High ({sev}{'; ' + top if top else ''}); {len(unfixed)} without an upstream fix "
              f"({'blocking' if block_unfixed else 'not blocking'}) — trivy {'image' if report.get('ArtifactType') == 'container_image' else 'fs'}")
    return not blocking, detail, None


def trivy_image(path):
    """Image scan plus "hardened base": digest-pinned base (checked in
    build) and a non-root USER."""
    ok, detail, _ = trivy(path)
    report = load(path) or {}
    user = ((report.get("Metadata") or {}).get("ImageConfig") or {}).get("config", {}).get("User", "").strip()
    root = user.split(":")[0] in ("", "0", "root")
    return ok and not root, f"base {env('BASE_IMAGE', '')[:37]}…; runs as {user or 'root (no USER)'}; {detail}", None


def checkov(path):
    """Open-source checkov has no severities, so every failed check blocks;
    exceptions are inline `checkov.io/skipN` annotations, counted here."""
    reports = load(path)
    if reports is None:
        return missing("checkov")
    reports = reports if isinstance(reports, list) else [reports]
    passed = sum(r["summary"]["passed"] for r in reports)
    failed = [c for r in reports for c in r["results"].get("failed_checks", [])]
    skipped = sorted({c["check_id"] for r in reports for c in r["results"].get("skipped_checks", [])})
    ids = ", ".join(sorted({f"{c['check_id']} ({c['resource']})" for c in failed})[:8])
    detail = (f"{len(failed)} failed, {passed} passed, {len(skipped)} skipped with inline justification"
              f"{' (' + ', '.join(skipped) + ')' if skipped else ''} — checkov on Dockerfile + kustomize build deploy/kind"
              f"{': ' + ids if ids else ''}")
    return not failed and passed > 0, detail, None


def sbom(path):
    bom = load(path)
    if bom is None:
        return missing("syft")
    n = len(bom.get("components") or [])
    return bom.get("bomFormat") == "CycloneDX" and n > 0, f"CycloneDX {bom.get('specVersion')} with {n} components (syft)", None


def signed():
    """A signature is the statement "this passed G2": only signed when every
    other G2 control passed (NOT_READY lists the ones that didn't), and a
    pass means the signature and attestations verify (VERIFY_FAILED)."""
    if env("NOT_READY"):
        return False, f"not signed: G2 controls failed ({env('NOT_READY')})", None
    if env("VERIFY_FAILED"):
        return False, f"signing ran but verification failed: {env('VERIFY_FAILED')}", None
    return True, ("cosign keyless signature + cyclonedx and slsaprovenance1 attestations verified for "
                  f"{env('CERT_IDENTITY', '').split('/', 5)[-1]} (public Rekor); GitHub build provenance attested"), None


# --- G3 ---------------------------------------------------------------------


def coverage(path):
    """A ratchet at the current baseline, not a quality claim — raise
    COVERAGE_THRESHOLD as tests are added (target 80)."""
    threshold = float(env("COVERAGE_THRESHOLD"))
    try:
        rate = ET.parse(path).getroot().get("line-rate")
    except (OSError, ET.ParseError):
        rate = None
    if rate is None:
        return False, "no coverage report", {"coverage_pct": 0.0, "threshold_pct": threshold}
    cov = float(rate) * 100
    return cov >= threshold, f"{cov:.1f}% line coverage vs ratchet {threshold:.0f}% (pytest-cov, tests/unit)", {"coverage_pct": round(cov, 2), "threshold_pct": threshold}


def k6(path):
    summary = load(path)
    if summary is None:
        return missing("k6")
    m = summary.get("metrics", {})
    val = lambda name, stat: (m.get(name, {}).get("values") or {}).get(stat)  # noqa: E731
    p95, failed, checks, slo = val("http_req_duration", "p(95)"), val("http_req_failed", "rate") or 0, val("checks", "rate") or 0, float(env("SLO_P95_MS"))
    if p95 is None:
        return False, "k6 summary has no http_req_duration", None
    ok = p95 <= slo and failed < 0.01 and checks >= 0.99
    detail = f"p95 {p95:.0f} ms vs SLO {slo:.0f} ms; {100 * failed:.1f}% failed requests, {100 * checks:.1f}% checks ok (k6: /login + /api/accounts)"
    return ok, detail, {"p95_ms": round(p95, 1), "slo_ms": slo}


def zap(path):
    report = load(path)
    if report is None:
        return missing("ZAP baseline")
    alerts = [a for s in report.get("site", []) for a in s.get("alerts", [])]
    high = [a for a in alerts if str(a.get("riskcode")) == "3"]
    medium = [a for a in alerts if str(a.get("riskcode")) == "2"]
    names = ", ".join(sorted({a.get("name", "?") for a in high})[:6])
    return not high, f"{len(high)} High, {len(medium)} Medium alert types — ZAP passive baseline, unauthenticated{': ' + names if names else ''}", None


def trivy_config(path):
    report = load(path)
    if report is None:
        return missing("trivy config")
    mis = [x for r in report.get("Results") or [] for x in r.get("Misconfigurations") or [] if x.get("Status") == "FAIL"]
    ids = ", ".join(sorted({x.get("ID", "?") for x in mis})[:8])
    return not mis, f"{len(mis)} High/Critical misconfigurations — trivy config (KSV incl. Pod Security Standards) on kustomize build deploy/kind{': ' + ids if ids else ''}", None


# --- G5 ---------------------------------------------------------------------


def kubeconform(path):
    """Render valid against schemas (-strict) AND the only change vs git
    is the image digest (CHANGED, space-separated paths)."""
    summary = (load(path) or {}).get("summary", {})
    valid = summary.get("valid", 0)
    total = sum(summary.get(k, 0) for k in ("valid", "invalid", "errors", "skipped"))
    changed = (env("CHANGED") or "").split()
    ok = env("RC") == "0" and total > 0 and valid == total and changed == ["deploy/kind/kustomization.yaml"]
    return ok, f"deploy/kind render: {valid}/{total} resources valid (kubeconform -strict, CRDs-catalog schemas); change vs git: {', '.join(changed) or 'none'} (image digest only)", None


# --- generic ----------------------------------------------------------------


def result(status, detail):
    """For controls decided in shell (API checks, verification commands)."""
    return status == "pass", detail, None


CHECKS = {f.__name__.replace("_", "-"): f for f in (
    reviewers, tests, semgrep, gitleaks, commits, build, trivy, trivy_image, checkov, sbom, signed,
    coverage, k6, zap, trivy_config, kubeconform, result,
)}


def main():
    check, args = sys.argv[1], sys.argv[2:]
    try:
        ok, detail, metrics = CHECKS[check](*args)
    except (OSError, ValueError, KeyError, ET.ParseError) as exc:
        ok, detail, metrics = False, f"{check}: could not evaluate ({type(exc).__name__}: {exc})", None
    out = {"status": "pass" if ok else "fail", "detail": detail[:1000]}
    if metrics:
        out["metrics"] = metrics
    print(f"{out['status']}: {detail}")
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"result={json.dumps(out)}\n")
    if not ok:
        print(f"::error::{check}: {detail[:500]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
