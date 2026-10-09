#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare the worked example in OSS Scanner's threat-model template with how the
maintainers in Anthropic's own published ledger actually rate those bug classes.

    src/template_check.py data/payload-r35.json

`templates/threat_model.md` in github.com/anthropics/oss-scanner carries one
worked example under "How you rate severity":

    any buffer overflow, use-after-free, or double free is high+ at a minimum

That file is the channel through which a maintainer tells the scanner their own
severity convention, and it is the only severity guidance a maintainer sees
before writing one. This script asks a narrow question: among findings in exactly
those classes, where a maintainer later published a severity of their own, how
many landed at or above that floor?

It counts each finding once. A finding can appear under a CVE and several GHSAs,
so iterating advisory records double-counts; `calibration.unique_findings` keys on
ant_id instead. Only findings carrying both a Claude band and a maintainer band
can be compared at all, which is a small and self-selected slice; the script
prints the project breakdown so the reader can weigh that themselves.
"""
import argparse
import json
import pathlib
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import calibration  # noqa: E402
import stats  # noqa: E402

# The classes the template's example names, and nothing else.
NAMED = {
    "heap-buffer-overflow", "stack-buffer-overflow", "buffer-overflow",
    "global-buffer-overflow", "use-after-free", "double-free",
}
FLOOR = stats.INDEX["high"]   # "high+ at a minimum"
BAND = {v: k for k, v in stats.INDEX.items()}


def report(document):
    findings = [f for f in calibration.unique_findings(document) if f["bug_class"] in NAMED]
    if not findings:
        return {"n": 0}

    def side(key):
        bands = [stats.INDEX[f[key]] for f in findings]
        below = [b for b in bands if b < FLOOR]
        return {
            "mean_band": sum(bands) / len(bands),
            "distribution": {BAND[b]: c for b, c in sorted(Counter(bands).items())},
            "below_floor": len(below),
            "below_floor_pct": 100 * len(below) / len(bands),
        }

    projects = {}
    for f in findings:
        projects.setdefault(f["project"], []).append(stats.INDEX[f["maintainer"]])

    # The two largest contributors removed, because a result carried by two
    # projects is a fact about two projects.
    largest = sorted(projects, key=lambda p: -len(projects[p]))[:2]
    kept = [f for f in findings if f["project"] not in largest]
    kept_bands = [stats.INDEX[f["maintainer"]] for f in kept]

    return {
        "n": len(findings),
        "projects": len(projects),
        "classes": dict(Counter(f["bug_class"] for f in findings)),
        "maintainer": side("maintainer"),
        "claude": side("claude"),
        "without_two_largest": {
            "dropped": largest,
            "n": len(kept),
            "mean_band": (sum(kept_bands) / len(kept_bands)) if kept_bands else None,
            "below_floor": sum(1 for b in kept_bands if b < FLOOR),
            "below_floor_pct": (100 * sum(1 for b in kept_bands if b < FLOOR) / len(kept_bands)) if kept_bands else None,
        },
        "by_project": sorted(
            ({"project": p, "n": len(v), "mean_band": sum(v) / len(v),
              "distribution": {BAND[b]: c for b, c in sorted(Counter(v).items())},
              "at_or_above_floor": sum(1 for b in v if b >= FLOOR)}
             for p, v in projects.items()),
            key=lambda r: (-r["n"], r["project"]),
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("snapshot", type=pathlib.Path)
    r = report(json.loads(parser.parse_args().snapshot.read_text(encoding="utf-8")))
    if not r["n"]:
        print("no findings in these classes carry both a Claude and a maintainer severity")
        return 1

    print(f'the template\'s example: "any buffer overflow, use-after-free, or double free is high+ at a minimum"\n')
    print(f"findings in exactly those classes, each counted once: n={r['n']} across {r['projects']} projects")
    print(f"  {r['classes']}\n")
    for who in ("maintainer", "claude"):
        s = r[who]
        print(f"  {who:<11} mean band {s['mean_band']:.2f}   {s['distribution']}")
        print(f"  {'':<11} below the floor: {s['below_floor']}/{r['n']} = {s['below_floor_pct']:.0f}%")
    w = r["without_two_largest"]
    print(f"\n  robustness, without {w['dropped']}:")
    print(f"    n={w['n']}  maintainer mean {w['mean_band']:.2f}  below the floor {w['below_floor']}/{w['n']} "
          f"= {w['below_floor_pct']:.0f}%")
    print("\n  by project, maintainer bands:")
    for row in r["by_project"]:
        print(f"    {row['project']:<30} n={row['n']:<3} mean {row['mean_band']:.2f}  "
              f"at/above floor {row['at_or_above_floor']}/{row['n']}  {row['distribution']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
