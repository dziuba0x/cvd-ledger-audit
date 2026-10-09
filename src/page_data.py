#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reduce the full audit report to the compact record the published page reads.

    src/page_data.py out/audit.json out/page-data.json

The page embeds its numbers rather than fetching them, so this is the one place
where the report and the page can drift apart. Keeping it as a script, rather
than as something typed once into a shell, is what makes the published figures
re-derivable from the pinned snapshot.
"""
import argparse
import json
import pathlib


def build(report):
    c = report["consistency"]
    cal = report["calibration"]
    cc = report["concentration"]
    pr = report["paired"]
    r3 = lambda v: round(v, 3) if isinstance(v, float) else v      # noqa: E731
    r1 = lambda v: round(v, 1) if isinstance(v, float) else v      # noqa: E731

    def band(row):
        return {k: r3(v) for k, v in row.items() if k != "confusion"}

    return {
        "snapshot": c["snapshot"],
        "hashes": c["hashes"],
        "sound": [[x["figure"], x["published"], x["recomputed"], x["ok"]] for x in report["soundness"]["reproduced"]],
        "all_reproduced": report["soundness"]["all_reproduced"],
        "agreement": [{
            "title": a["title"], "why": a["why"], "n": a["n"],
            "exact": r1(a["exact_pct"]), "within1": r1(a["within_one_pct"]), "chance": r1(a["chance_pct"]),
            "kappa": r3(a["kappa"]), "lo": r3(a["kappa_ci"]["lo95"]), "hi": r3(a["kappa_ci"]["hi95"]),
            "qwk": r3(a["quadratic_kappa"]), "gap": r3(a["mean_gap"]),
            "hotter": r1(a["left_higher_pct"]), "cooler": r1(a["left_lower_pct"]),
            "confusion": a["confusion"], "rows": a["row_marginals"], "cols": a["column_marginals"],
        } for a in report["agreement"] if a["n"]],
        "paired": {
            "n": pr["n"],
            "claude": band(pr["claude"]), "vendor": band(pr["vendor"]),
            "kappa_difference": {k: r3(v) for k, v in pr["kappa_difference"].items()},
            "gap_difference": {k: r3(v) for k, v in pr["gap_difference"].items()},
            "finders": {k: r3(v) for k, v in pr["finders_against_each_other"].items()},
            "clustered": {k: ({kk: r3(vv) for kk, vv in v.items()} if isinstance(v, dict) else v)
                          for k, v in pr["clustered"].items()},
        },
        "concentration": {k: (r1(v) if isinstance(v, float) else v)
                          for k, v in cc.items() if k not in ("top_dates", "by_month")} | {
            "top_dates": [{kk: r1(vv) for kk, vv in d.items()} for d in cc["top_dates"]],
            "by_month": [{kk: r1(vv) for kk, vv in m.items()} for m in cc["by_month"]],
        },
        "calibration": {
            "largest_sample": {k: (round(v, 3) if isinstance(v, float) else v)
                               for k, v in cal["largest_sample"].items()},
            "bucket_robustness": [{k: (round(v, 3) if isinstance(v, float) else v) for k, v in b.items()}
                                  for b in cal["bucket_robustness"]],
            "deduplication": cal["deduplication"],
            "pooled": {k: r3(v) for k, v in cal["pooled"].items()},
            "buckets": [{k: r3(v) for k, v in b.items()} for b in cal["buckets"] if b["n"]],
            "per_class": [{k: r3(v) for k, v in c2.items()} for c2 in cal["per_class_indicative"]],
            "too_thin": cal["per_class_too_thin"],
            "min_per_class": cal["min_per_class"],
            "lopo": [{k: r3(v) for k, v in row.items()} for row in cal["leave_one_project_out"]],
            "representativeness": {
                "slice_size": cal["representativeness"]["slice_size"],
                "population": cal["representativeness"]["population"],
                "share_pct": round(cal["representativeness"]["slice_share_of_population_pct"], 2),
                "classes": [{k: r1(v) for k, v in row.items()}
                            for row in cal["representativeness"]["classes"][:6]],
            },
        },
        "consistency": c["checks"],
        "open_count": c["open_count"],
        "detail": {"entries": c["ledger_entries"], "with_detail": c["entries_with_detail"],
                   "share": r1(c["detail_share_pct"])},
        "tiers": c["reveal_tiers"],
        "patch": c["patch_acceptance"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("out", type=pathlib.Path)
    options = parser.parse_args()
    data = build(json.loads(options.report.read_text(encoding="utf-8")))
    options.out.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    print(f"{options.out}  {len(options.out.read_bytes()):,} bytes")


if __name__ == "__main__":
    main()
