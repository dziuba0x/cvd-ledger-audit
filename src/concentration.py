#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Whether the published agreement figure is spread across the corpus or carried by one batch.

    src/concentration.py data/payload-r35.json

Anthropic reports 83.0% exact severity agreement between Claude and the external
triage firms over 1,337 findings. The figure reproduces. What the figure does not
say is that the findings are not independent: they carry a discovery date, there
are only 50 distinct dates, and one of them supplies almost half the set.

This module measures that concentration and reports agreement with and without
the dominant batch. It also reports agreement by month, because a reader who sees
a single pooled number will reasonably assume it is a stable property.
"""
import argparse
import json
import pathlib
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import stats  # noqa: E402


def paired(document, left="claude_sev", right="vendor_sev"):
    """Findings where both raters assigned a band, keeping the discovery date."""
    out = []
    for p in document["severity_pairs"]:
        a, b = stats.INDEX.get(p.get(left)), stats.INDEX.get(p.get(right))
        if a is not None and b is not None:
            out.append({"a": a, "b": b, "date": p.get("discovered_on")})
    return out


def exact_rate(rows):
    """Share of rows where the two raters chose the same band."""
    return (100 * sum(1 for r in rows if r["a"] == r["b"]) / len(rows)) if rows else None


def report(document):
    rows = paired(document)
    dates = Counter(r["date"] for r in rows)
    dominant, dominant_n = dates.most_common(1)[0]

    inside = [r for r in rows if r["date"] == dominant]
    outside = [r for r in rows if r["date"] != dominant]

    by_month = {}
    for r in rows:
        month = (r["date"] or "unknown")[:7]
        by_month.setdefault(month, []).append(r)

    groups = {}
    for r in rows:
        groups.setdefault(r["date"], []).append(1.0 if r["a"] == r["b"] else 0.0)
    clustered = stats.cluster_bootstrap(groups, stats.mean) or {}

    return {
        "n": len(rows),
        "distinct_dates": len(dates),
        "pooled_exact_pct": exact_rate(rows),
        "dominant_date": dominant,
        "dominant_n": dominant_n,
        "dominant_share_pct": 100 * dominant_n / len(rows),
        "dominant_exact_pct": exact_rate(inside),
        "without_dominant_n": len(outside),
        "without_dominant_exact_pct": exact_rate(outside),
        # The pooled rate as an interval that respects the batching.
        "clustered_lo95_pct": 100 * clustered["lo95"] if clustered.get("lo95") is not None else None,
        "clustered_hi95_pct": 100 * clustered["hi95"] if clustered.get("hi95") is not None else None,
        "top_dates": [
            {"date": d, "n": n, "share_pct": 100 * n / len(rows),
             "exact_pct": exact_rate([r for r in rows if r["date"] == d])}
            for d, n in dates.most_common(6)
        ],
        "by_month": [
            {"month": m, "n": len(v), "exact_pct": exact_rate(v)}
            for m, v in sorted(by_month.items()) if len(v) >= 20
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("snapshot", type=pathlib.Path)
    r = report(json.loads(parser.parse_args().snapshot.read_text(encoding="utf-8")))

    print(f"paired findings: {r['n']:,} across {r['distinct_dates']} discovery dates\n")
    print(f"  pooled, as published        {r['pooled_exact_pct']:.1f}%")
    print(f"  the {r['dominant_date']} batch   {r['dominant_exact_pct']:.1f}%  "
          f"(n={r['dominant_n']}, {r['dominant_share_pct']:.1f}% of all evidence)")
    print(f"  everything else             {r['without_dominant_exact_pct']:.1f}%  (n={r['without_dominant_n']})")
    print(f"  pooled, date-clustered 95%  [{r['clustered_lo95_pct']:.1f}%, {r['clustered_hi95_pct']:.1f}%]")
    print("\n  largest discovery dates:")
    for d in r["top_dates"]:
        print(f"    {d['date']}  n={d['n']:<5} {d['share_pct']:5.1f}% of set   exact {d['exact_pct']:5.1f}%")
    print("\n  by discovery month (n >= 20):")
    for m in r["by_month"]:
        print(f"    {m['month']}  n={m['n']:<5} exact {m['exact_pct']:5.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
