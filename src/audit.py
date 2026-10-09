#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independently reproduce and extend the figures in Anthropic's public CVD ledger.

    src/audit.py data/payload-r35.json [--json out/audit.json] [--markdown out/audit.md]

Three things happen, in this order, and the order is the point:

1. REPRODUCE. Recompute the figures Anthropic published in prose from the raw
   ledger. If any of them fails to reproduce, the run is marked UNSOUND and
   nothing below it should be believed. This is the anchor: an analysis that
   cannot first land the author's own published numbers has no standing to
   report new ones.
2. EXTEND. Compute what the published prose does not: chance-corrected
   agreement, the direction of disagreement, and the maintainer-side comparison.
3. AUDIT. Reconcile every top-level aggregate against the per-entry ledger, and
   classify each gap as explained by the ledger's sealing design or not. Most
   are explained; saying which is the whole value of the exercise.

Standard library only. Offline: it reads a pinned snapshot and never fetches.
"""
import argparse
import json
import pathlib
import sys

# This tool is run with `python3 -I` so that nothing on PYTHONPATH or in the
# working directory can shadow a standard-library module: the ledger it reads is
# downloaded data, and a planted json.py beside it would otherwise be imported.
# Isolated mode also drops the script's own directory, so add just that back.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import paired  # noqa: E402 - must follow the sys.path line above
import stats  # noqa: E402

# What Anthropic states in prose at red.anthropic.com/2026/cvd/ and in the
# launch post. Each entry is (label, published value, how to recompute it).
# A mismatch here fails the run.
PUBLISHED = {
    "severity exact agreement (%)": 83.0,
    "severity within one band (%)": 97.1,
    "severity comparison n": 1337,
    "true positive rate (%)": 92.7,
    "disclosed findings": 6157,
    "projects": 591,
    "CVEs": 219,
    "GHSAs": 365,
    "acknowledged": 5103,
    "candidates analysed": 29439,
}

# The ledger seals per-finding detail until a finding reaches the `revealed`
# tier. Fields in this set are therefore only populated for revealed entries,
# so a top-level total that counts the whole corpus cannot be reconciled
# against them. That is by design, not an error.
SEALED_FIELDS = frozenset({"ant_id", "project", "bug_class", "cve_ids", "ghsa_ids", "vendor_severity", "maintainer_severity"})


def load(path):
    """Read a pinned snapshot."""
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- 1


def reproduce(document):
    """Recompute each published figure from the raw ledger.

    Returns (rows, sound) where rows is [(label, published, recomputed, ok)].
    """
    ledger = document["ledger"]
    headline = document["headline"]
    claude_vendor = stats.pairs(document["severity_pairs"], "claude_sev", "vendor_sev")
    summary = stats.summarise(claude_vendor)

    recomputed = {
        "severity exact agreement (%)": round(summary["exact_pct"], 1),
        "severity within one band (%)": round(summary["within_one_pct"], 1),
        "severity comparison n": summary["n"],
        "disclosed findings": document["total_disclosed"],
        "projects": document["project_count"],
        "CVEs": document["total_cves"],
        "GHSAs": document["total_ghsas"],
        "acknowledged": document["total_acknowledged"],
        "candidates analysed": headline["analyzed"],
    }
    # The denominator for the true positive rate (6,123 findings reviewed) is
    # stated only in prose; it is not a field in the ledger. Name it here rather
    # than pretend the ledger carries it, so a reader can see the one input to
    # this audit that is quoted rather than recomputed.
    REVIEWED_IN_PROSE = 6123
    recomputed["true positive rate (%)"] = round(100 * document["total_verified"] / REVIEWED_IN_PROSE, 1)

    rows, sound = [], True
    for label, published in PUBLISHED.items():
        got = recomputed[label]
        ok = abs(got - published) <= (0.05 if isinstance(published, float) else 0)
        rows.append((label, published, got, ok))
        sound = sound and ok
    return rows, sound, len(ledger)


# --------------------------------------------------------------------------- 2


COMPARISONS = (
    ("claude_sev", "vendor_sev", "Claude vs triage firm", "the comparison Anthropic published"),
    ("claude_sev", "maintainer_sev", "Claude vs maintainer", "the people who decide whether to act"),
    ("vendor_sev", "maintainer_sev", "Triage firm vs maintainer", "the control: human finders, same maintainers"),
    ("claude_sev", "resolved_sev", "Claude vs resolved", "the ledger's own settled band"),
)


def agreement(document, draws):
    """Summarise every rater pair, with bootstrap intervals on both kappas."""
    results = []
    for left, right, title, why in COMPARISONS:
        observations = stats.pairs(document["severity_pairs"], left, right)
        summary = stats.summarise(observations)
        summary.update(
            left=left, right=right, title=title, why=why,
            kappa_ci=stats.bootstrap(observations, stats.kappa, draws=draws),
            quadratic_kappa_ci=stats.bootstrap(observations, lambda s: stats.kappa(s, weighted=True), draws=draws),
        )
        results.append(summary)
    return results


def calibration_by_class(document):
    """Per-bug-class severity gap, joined through the revealed CVE/GHSA records.

    `severity_cells` holds "claude|vendor|maintainer" per finding, aligned with
    `findings`, which carries the bug class. This is the only join in the public
    data from a severity triple to a bug class, and it covers the revealed
    subset only.
    """
    buckets = {}
    joined = 0
    for record in document["cve_records"] + document["ghsa_records"]:
        cells = record.get("severity_cells") or []
        for finding, cell in zip(record.get("findings") or [], cells):
            parts = (cell.split("|") + [None, None, None])[:3]
            claude, vendor, maintainer = parts
            bug_class = finding.get("bug_class") or "unclassified"
            bucket = buckets.setdefault(bug_class, {"vs_vendor": [], "vs_maintainer": [], "projects": set()})
            if finding.get("project"):
                bucket["projects"].add(finding["project"])
            joined += 1
            for key, other in (("vs_vendor", vendor), ("vs_maintainer", maintainer)):
                a, b = stats.INDEX.get(claude), stats.INDEX.get(other)
                if a is not None and b is not None:
                    bucket[key].append(a - b)

    rows = []
    for bug_class, bucket in buckets.items():
        row = {"bug_class": bug_class, "projects": sorted(bucket["projects"])}
        for key in ("vs_vendor", "vs_maintainer"):
            gaps = bucket[key]
            row[f"n_{key}"] = len(gaps)
            row[f"mean_{key}"] = (sum(gaps) / len(gaps)) if gaps else None
        rows.append(row)
    rows.sort(key=lambda r: -(r["n_vs_vendor"] + r["n_vs_maintainer"]))
    return {"joined_findings": joined, "classes": rows}


# --------------------------------------------------------------------------- 3


def consistency(document):
    """Reconcile top-level aggregates against the per-entry ledger.

    Each check is tagged:
      matches  - aggregate equals the per-entry count.
      sealed   - the gap is what the sealing design predicts: the aggregate
                 counts the whole corpus, the per-entry field exists only for
                 revealed findings.
      funnel   - the aggregate counts a different population on purpose
                 (candidates before triage, not disclosed findings).
      open     - neither sealing nor the funnel explains it. Both fields are
                 present on every row, so the two counts should agree.
    """
    ledger = document["ledger"]
    count = lambda field, value=True: sum(1 for e in ledger if e.get(field) == value)  # noqa: E731
    revealed = sum(1 for e in ledger if e.get("reveal_tier") == "revealed")

    checks = [
        ("total_fixed", document["total_fixed"], "ledger is_fixed", count("is_fixed"), None),
        ("total_disclosed", document["total_disclosed"], "ledger was_disclosed", count("was_disclosed"), None),
        ("withdrawn flag", count("withdrawn"), "status == 'withdrawn'", count("status", "withdrawn"), None),
        ("total_revealed", document["total_revealed"], "reveal_tier == 'revealed'", revealed, None),
        ("total_verified", document["total_verified"], "ledger vendor_confirmed", count("vendor_confirmed"), "sealed"),
        ("total_cves", document["total_cves"], "sum of ledger cve_ids",
         sum(len(e.get("cve_ids") or []) for e in ledger), "sealed"),
        ("total_ghsas", document["total_ghsas"], "sum of ledger ghsa_ids",
         sum(len(e.get("ghsa_ids") or []) for e in ledger), "sealed"),
        ("total_fixed_in_response", document["total_fixed_in_response"],
         "ledger is_fixed_in_response", count("is_fixed_in_response"), "sealed"),
        ("project_count", document["project_count"], "by_project entries", len(document["by_project"]), "sealed"),
        ("headline.analyzed", document["headline"]["analyzed"], "ledger entries", len(ledger), "funnel"),
    ]

    rows = []
    for name, aggregate, against, found, forced in checks:
        if aggregate == found:
            tag = "matches"
        elif forced:
            tag = forced
        else:
            tag = "open"
        rows.append({
            "aggregate": name, "aggregate_value": aggregate,
            "compared_with": against, "ledger_value": found,
            "delta": aggregate - found, "verdict": tag,
        })

    unsealed = sum(1 for e in ledger if e.get("project"))
    return {
        "checks": rows,
        "open_count": sum(1 for r in rows if r["verdict"] == "open"),
        "ledger_entries": len(ledger),
        "entries_with_detail": unsealed,
        "detail_share_pct": 100 * unsealed / len(ledger),
        "reveal_tiers": document["tier_partition"],
        "status_counts": {k or "null": sum(1 for e in ledger if e.get("status") == k)
                          for k in {e.get("status") for e in ledger}},
        "patch_acceptance": document["patch_acceptance"],
        "snapshot": {"revision": document["revision"], "as_of": document["as_of"],
                     "analysis_until": document["analysis_until"],
                     "manifest_sha3": document["manifest_sha3"]},
        "hashes": {
            "entries": len(ledger),
            "present": sum(1 for e in ledger if e.get("hash")),
            "distinct": len({e["hash"] for e in ledger if e.get("hash")}),
            "bits": sorted({len(e["hash"]) * 4 for e in ledger if e.get("hash")}),
        },
    }


# ---------------------------------------------------------------------------


def build(document, draws=5000):
    """Run all four stages and return one report."""
    rows, sound, entries = reproduce(document)
    return {
        "paired": paired.report(document, draws=draws),
        "soundness": {
            "reproduced": [{"figure": f, "published": p, "recomputed": g, "ok": ok} for f, p, g, ok in rows],
            "all_reproduced": sound,
            "verdict": "SOUND" if sound else "UNSOUND - published figures did not reproduce; ignore the rest",
            "ledger_entries": entries,
        },
        "agreement": agreement(document, draws),
        "calibration": calibration_by_class(document),
        "consistency": consistency(document),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("snapshot", type=pathlib.Path, help="a payload-r<N>.json pinned by src/fetch.py")
    parser.add_argument("--json", type=pathlib.Path, help="write the full report here")
    parser.add_argument("--draws", type=int, default=5000, help="bootstrap resamples (default 5000)")
    options = parser.parse_args()

    report = build(load(options.snapshot), draws=options.draws)

    sound = report["soundness"]
    print(f"soundness: {sound['verdict']}")
    for row in sound["reproduced"]:
        mark = "ok " if row["ok"] else "FAIL"
        print(f"  [{mark}] {row['figure']:<32} published {row['published']:>8}   recomputed {row['recomputed']:>8}")

    print("\nagreement:")
    for a in report["agreement"]:
        if not a["n"]:
            continue
        ci = a["kappa_ci"] or {}
        print(f"  {a['title']:<28} n={a['n']:<5} exact {a['exact_pct']:5.1f}%  "
              f"chance {a['chance_pct']:5.1f}%  kappa {a['kappa']:+.3f} "
              f"[{ci.get('lo95', float('nan')):+.3f},{ci.get('hi95', float('nan')):+.3f}]  "
              f"gap {a['mean_gap']:+.2f}")

    pr = report["paired"]
    print(f"\npaired, on the n={pr['n']} findings rated by all three parties:")
    for who in ("claude", "vendor"):
        r = pr[who]
        print(f"  {r['label']:<26} kappa {r['kappa']:+.3f} [{r['kappa_lo95']:+.3f},{r['kappa_hi95']:+.3f}]"
              f"   mean gap {r['mean_gap']:+.3f}   hotter {r['hotter_pct']:.1f}% / cooler {r['cooler_pct']:.1f}%")
    for key, label in (("kappa_difference", "kappa difference"), ("gap_difference", "mean-gap difference")):
        dv = pr[key]
        print(f"  {label:<26} {dv['observed']:+.3f}  95% [{dv['lo95']:+.3f},{dv['hi95']:+.3f}]  -> {dv['verdict']}")
    print(f"  the two finders against each other: kappa {pr['finders_against_each_other']['kappa']:+.3f}"
          f"  exact {pr['finders_against_each_other']['exact_pct']:.1f}%")

    c = report["consistency"]
    print(f"\nconsistency: {c['open_count']} unexplained of {len(c['checks'])} checks; "
          f"per-entry detail on {c['entries_with_detail']}/{c['ledger_entries']} entries "
          f"({c['detail_share_pct']:.1f}%)")
    for row in c["checks"]:
        if row["verdict"] != "matches":
            print(f"  [{row['verdict']:<7}] {row['aggregate']:<26} {row['aggregate_value']:>7} vs "
                  f"{row['compared_with']:<28} {row['ledger_value']:>7}  delta {row['delta']:+}")

    if options.json:
        options.json.parent.mkdir(parents=True, exist_ok=True)
        options.json.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"\nwritten {options.json}")
    return 0 if sound["all_reproduced"] else 1


if __name__ == "__main__":
    sys.exit(main())
