"""Assemble one gate decision from its control jobs' verdicts.

Every gate is: the listed controls each ran (a job per control, see
verdict.py) and each passed. This file is the single list of which job
answers which dashboard criterion (keys: the dashboard's
docs/GATE_INGEST_API.md). A control job that crashed, was cancelled or
skipped left no verdict — that's a fail, never an implicit pass.

    NEEDS='${{ toJSON(needs) }}' python3 .github/scripts/gate.py G1 out.json

Writes gate-result.json (a GateEvaluationIn body), the job summary, and
`status=pass|fail` to $GITHUB_OUTPUT.
"""

import datetime as dt
import json
import os
import sys

# gate → [(job id in the gate's workflow, criterion key, category)]
GATES = {
    "G1": [
        ("reviewers", "required_reviewers_approved", "governance"),
        ("unit-tests", "unit_tests_pass", "quality"),
        ("sast", "sast_clean", "security"),
        ("secrets", "secrets_clean", "security"),
        ("commits-signed", "commits_signed", "security"),
    ],
    "G2": [
        ("build", "reproducible_build_config_controlled", "delivery"),
        ("sca", "sca_clean", "security"),
        ("iac", "iac_clean", "security"),
        ("image-scan", "container_image_scan_hardened_base", "security"),
        ("sign", "artifact_signed_attested", "security"),
        ("sbom", "sbom_present", "security"),
    ],
    "G3": [
        ("functional", "functional_integration_regression_pass", "quality"),
        ("performance", "performance_within_slo", "quality"),
        ("coverage", "coverage_threshold_met", "quality"),
        ("dast", "dast_scan_clean", "security"),
        ("compliance", "compliance_scan_clean", "security"),
    ],
    "G5": [
        ("provenance", "artifact_provenance_verified", "security"),
        ("config", "target_env_config_controlled", "delivery"),
        ("deploy", "approved_gitops_pipeline_path", "governance"),
    ],
}


def criterion(needs, job, key, category):
    j = needs.get(job) or {}
    try:
        verdict = json.loads((j.get("outputs") or {}).get("result") or "")
    except ValueError:
        verdict = None
    if not verdict or verdict.get("status") not in ("pass", "fail"):
        verdict = {"status": "fail", "detail": f"control did not complete (job {job}: {j.get('result', 'not run')})"}
    return {"key": key, "category": category, **verdict}


def main():
    gate, path = sys.argv[1], sys.argv[2]
    e = os.environ.get
    needs = json.loads(e("NEEDS") or "{}")
    criteria = [criterion(needs, *c) for c in GATES[gate]]
    status = "pass" if all(c["status"] == "pass" for c in criteria) else "fail"
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    body = {
        # product/source/run_url are overwritten by the dashboard from the
        # run it downloads this from; here so the file reads standalone.
        "product": "alienbank",
        "gate": gate,
        "status": status,
        "source": "github-actions",
        "subject": e("SUBJECT"),
        "external_id": f"gh-{e('GITHUB_RUN_ID')}-{e('GITHUB_RUN_ATTEMPT')}-{gate}",
        "commit_sha": e("COMMIT_SHA") or e("GITHUB_SHA"),
        "artifact_digest": e("DIGEST") or None,
        "environment": e("ENVIRONMENT") or None,
        "run_url": f"{e('GITHUB_SERVER_URL')}/{e('GITHUB_REPOSITORY')}/actions/runs/{e('GITHUB_RUN_ID')}",
        "started_at": e("STARTED_AT") or now,
        "finished_at": now,
        "criteria": criteria,
    }
    with open(path, "w") as f:
        json.dump(body, f, indent=2)
    with open(e("GITHUB_STEP_SUMMARY"), "a") as f:
        f.write(f"### {gate}: {status}\n\n" + "".join(f"- **{c['status']}** `{c['key']}` — {c['detail']}\n" for c in criteria))
    for c in criteria:
        print(f"{c['status']:>4}  {c['key']}: {c['detail']}")
    with open(e("GITHUB_OUTPUT"), "a") as f:
        f.write(f"status={status}\n")


if __name__ == "__main__":
    main()
