"""Writes tests_passed/tests_total/coverage_pct to $GITHUB_OUTPUT.

Handles both <testsuites> and bare <testsuite> roots. A test counts as
passed only if it has no <failure>, <error> or <skipped> child — skipped
tests are excluded from the total rather than counted as passes, so a
suite that skips everything can't report 100%.
"""

import glob
import os
import xml.etree.ElementTree as ET

passed = total = 0
for path in glob.glob(os.environ.get("JUNIT_GLOB") or "**/junit*.xml", recursive=True):
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        print(f"::warning::Unparseable JUnit file {path}")
        continue
    for case in root.iter("testcase"):
        tags = {child.tag for child in case}
        if "skipped" in tags:
            continue
        total += 1
        if not tags & {"failure", "error"}:
            passed += 1

coverage = ""
cov_file = os.environ.get("COVERAGE_FILE", "")
if cov_file and os.path.exists(cov_file):
    rate = ET.parse(cov_file).getroot().get("line-rate")
    if rate is not None:
        coverage = f"{float(rate) * 100:.2f}"

print(f"tests: {passed}/{total} passed; coverage: {coverage or 'n/a'}")
with open(os.environ["GITHUB_OUTPUT"], "a") as out:
    out.write(f"tests_passed={passed}\ntests_total={total}\ncoverage_pct={coverage}\n")
