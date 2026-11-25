#!/usr/bin/env python3
"""Print a per-test skip report and a grand total from surefire/failsafe XML reports."""
import glob
import os
import sys
import xml.etree.ElementTree as ET

root = sys.argv[1] if len(sys.argv) > 1 else "."
patterns = [
    os.path.join(root, "**", "target", "surefire-reports", "TEST-*.xml"),
    os.path.join(root, "**", "target", "failsafe-reports", "TEST-*.xml"),
]
files = sorted({f for p in patterns for f in glob.glob(p, recursive=True)})

total = failures = errors = skipped = 0
skips = []
for path in files:
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        print("WARN: cannot parse %s: %s" % (path, exc))
        continue
    suite = tree.getroot()
    for case in suite.iter("testcase"):
        total += 1
        if case.find("failure") is not None:
            failures += 1
        elif case.find("error") is not None:
            errors += 1
        else:
            skip = case.find("skipped")
            if skip is not None:
                skipped += 1
                reason = (skip.get("message") or (skip.text or "").strip() or "@Ignore (no message)")
                reason = " ".join(reason.split())[:200]
                skips.append("%s.%s: %s" % (case.get("classname"), case.get("name"), reason))

print("=== Seal test summary (%d report files) ===" % len(files))
for line in skips:
    print("SKIPPED %s" % line)
passed = total - failures - errors - skipped
print(
    "TOTAL: tests run=%d, passed=%d, failures=%d, errors=%d, skipped=%d"
    % (total, passed, failures, errors, skipped)
)
