#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""How far finder-side severity sits above the maintainer's own, measured honestly.

    src/calibration.py data/payload-r35.json

Two corrections sit behind every figure here, and both change the answer.

DEDUPLICATION. The ledger exposes a severity triple only through its revealed CVE
and GHSA records, and one finding can appear under several advisory identifiers:
157 advisory slots carry just 98 distinct ant_ids, and one finding appears four
times (one CVE and three GHSAs). Counting slots inflates every class mean. This
module counts each ant_id once.

CLUSTERING. What is left is not 66 independent observations. Two projects supply
12 findings each, so an interval that resamples findings is too narrow. Every
interval here resamples whole projects.

What survives those two corrections is a pooled figure and three coarse buckets.
A per-class table does not: after deduplication most classes rest on one to three
findings, and publishing `code-injection -1.00` from a single finding would be
fabricating precision. `per_class` is therefore computed but marked indicative,
and the generated outputs use the buckets.
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import stats  # noqa: E402

# Grouped by the kind of mistake, not by the sanitizer that happens to catch it.
BUCKETS = {
    "spatial memory corruption": {
        "heap-buffer-overflow", "stack-buffer-overflow", "buffer-overflow",
        "global-buffer-overflow", "oob-write", "off-by-one",
    },
    "temporal and arithmetic": {
        "use-after-free", "double-free", "integer-overflow", "integer-underflow",
    },
}
OTHER = "everything else"
MIN_PER_CLASS = 5  # below this a class mean is noise; reported, never published as a lookup


def unique_findings(document):
    """Every finding with a Claude and a maintainer severity, counted once.

    Returns a list of dicts. `gap` is positive when Claude placed the finding
    above the maintainer, in severity bands.
    """
    seen, out = set(), []
    for record in document["cve_records"] + document["ghsa_records"]:
        cells = record.get("severity_cells") or []
        for finding, cell in zip(record.get("findings") or [], cells):
            ant_id = finding.get("ant_id")
            if not ant_id or ant_id in seen:
                continue
            claude, vendor, maintainer = (cell.split("|") + [None, None, None])[:3]
            c, m = stats.INDEX.get(claude), stats.INDEX.get(maintainer)
            if c is None or m is None:
                continue
            seen.add(ant_id)
            out.append({
                "ant_id": ant_id,
                "bug_class": finding.get("bug_class") or "unclassified",
                "project": finding.get("project") or "unknown",
                "claude": claude, "vendor": vendor, "maintainer": maintainer,
                "gap": c - m,
            })
    return out


def bucket_of(bug_class):
    """Which coarse bucket a bug class belongs to."""
    for name, members in BUCKETS.items():
        if bug_class in members:
            return name
    return OTHER


def _by_project(findings):
    """Group gaps by project, which is the cluster the bootstrap resamples."""
    groups = {}
    for f in findings:
        groups.setdefault(f["project"], []).append(f["gap"])
    return groups


def summarise(findings, label):
    """Mean gap for a set of findings, with a project-clustered interval."""
    if not findings:
        return {"label": label, "n": 0}
    gaps = [f["gap"] for f in findings]
    groups = _by_project(findings)
    interval = stats.cluster_bootstrap(groups, stats.mean) or {}
    return {
        "label": label,
        "n": len(gaps),
        "projects": len(groups),
        "mean_gap": sum(gaps) / len(gaps),
        "lo95": interval.get("lo95"),
        "hi95": interval.get("hi95"),
        "excludes_zero": interval.get("excludes_zero"),
        "above_pct": 100 * sum(1 for g in gaps if g > 0) / len(gaps),
        "equal_pct": 100 * sum(1 for g in gaps if g == 0) / len(gaps),
        "below_pct": 100 * sum(1 for g in gaps if g < 0) / len(gaps),
    }


def leave_one_project_out(findings):
    """Re-pool with each of the largest contributors removed, to show nothing rests on one project."""
    groups = _by_project(findings)
    largest = sorted(groups, key=lambda p: -len(groups[p]))[:5]
    out = []
    for project in largest:
        kept = [f for f in findings if f["project"] != project]
        out.append({
            "dropped": project, "dropped_n": len(groups[project]),
            "remaining_n": len(kept),
            "mean_gap": (sum(f["gap"] for f in kept) / len(kept)) if kept else None,
        })
    return out


def representativeness(document, findings):
    """How unlike the whole corpus this measured slice is.

    The slice exists only where a maintainer published an advisory, so its class
    mix is nothing like the population the scanner actually reports on. Anyone
    reading a per-class figure needs this in front of them.
    """
    population = document["by_bug_class"]
    total = sum(population.values())
    slice_counts = {}
    for f in findings:
        slice_counts[f["bug_class"]] = slice_counts.get(f["bug_class"], 0) + 1
    rows = []
    for bug_class, count in sorted(slice_counts.items(), key=lambda kv: -kv[1]):
        rows.append({
            "bug_class": bug_class,
            "slice_n": count,
            "slice_pct": 100 * count / len(findings),
            "population_n": population.get(bug_class, 0),
            "population_pct": 100 * population.get(bug_class, 0) / total,
        })
    return {
        "slice_size": len(findings),
        "revealed_rows": document["total_revealed"],
        "population": total,
        "slice_share_of_population_pct": 100 * len(findings) / total,
        "classes": rows,
    }


def largest_sample(document):
    """The gap on every finding that carries both a Claude and a maintainer band.

    This is the figure to quote. `severity_pairs` already holds one row per
    finding, so nothing needs deduplicating, and at n=163 it is the largest
    sample available. The bucket analysis below runs on a subset of it — the
    findings that also reached a published advisory, which is where a bug class
    can be read — and that subset is measurably hotter, so the buckets must never
    be quoted as if they described the whole.
    """
    rows = []
    for pair in document["severity_pairs"]:
        c, m = stats.INDEX.get(pair.get("claude_sev")), stats.INDEX.get(pair.get("maintainer_sev"))
        if c is not None and m is not None:
            rows.append({"gap": c - m, "ant_id": pair.get("ant_id"),
                         "maintainer": pair.get("maintainer_sev")})
    gaps = [r["gap"] for r in rows]
    revealed = [r["gap"] for r in rows if r["ant_id"]]
    rest = [r["gap"] for r in rows if not r["ant_id"]]
    pooled = stats.bootstrap([(g, 0) for g in gaps], lambda s: stats.mean([a for a, _ in s])) or {}
    return {
        "n": len(gaps),
        "mean_gap": stats.mean(gaps),
        "lo95": pooled.get("lo95"), "hi95": pooled.get("hi95"),
        "advisory_revealed_n": len(revealed), "advisory_revealed_gap": stats.mean(revealed),
        "rest_n": len(rest), "rest_gap": stats.mean(rest),
        "selection_gap": (stats.mean(revealed) - stats.mean(rest)) if revealed and rest else None,
    }


def bucket_robustness(findings):
    """What each bucket becomes without its two largest contributing projects.

    A bucket mean carried by two projects is a fact about those two projects. The
    spatial bucket is the case that matters: it does not survive this.
    """
    out = []
    for name in list(BUCKETS) + [OTHER]:
        members = [f for f in findings if bucket_of(f["bug_class"]) == name]
        if not members:
            continue
        counts = {}
        for f in members:
            counts[f["project"]] = counts.get(f["project"], 0) + 1
        top = sorted(counts, key=lambda k: -counts[k])[:2]
        kept = [f for f in members if f["project"] not in top]
        out.append({
            "label": name, "n": len(members),
            "mean_gap": stats.mean([f["gap"] for f in members]),
            "top_two": top,
            "top_two_share_pct": 100 * sum(counts[t] for t in top) / len(members),
            "without_top_two_n": len(kept),
            "without_top_two_gap": stats.mean([f["gap"] for f in kept]),
        })
    return out


def report(document):
    """Everything this module stands behind, plus what it refuses to stand behind."""
    findings = unique_findings(document)
    slots = sum(len(r.get("severity_cells") or []) for r in document["cve_records"] + document["ghsa_records"])

    buckets = [summarise([f for f in findings if bucket_of(f["bug_class"]) == name], name)
               for name in list(BUCKETS) + [OTHER]]

    per_class = {}
    for f in findings:
        per_class.setdefault(f["bug_class"], []).append(f)
    classes = sorted((summarise(v, k) for k, v in per_class.items()), key=lambda r: -r["n"])

    return {
        "largest_sample": largest_sample(document),
        "bucket_robustness": bucket_robustness(findings),
        "deduplication": {
            "advisory_slots": slots,
            "unique_findings": len(findings),
            "repeats_removed": slots - len(findings),
            "note": "One finding can carry a CVE and several GHSAs. Counting advisory slots "
                    "counts it once per identifier and inflates every class mean.",
        },
        "pooled": summarise(findings, "all classes, pooled"),
        "buckets": buckets,
        "per_class_indicative": [c for c in classes if c["n"] >= MIN_PER_CLASS],
        "per_class_too_thin": [{"label": c["label"], "n": c["n"]} for c in classes if c["n"] < MIN_PER_CLASS],
        "min_per_class": MIN_PER_CLASS,
        "leave_one_project_out": leave_one_project_out(findings),
        "representativeness": representativeness(document, findings),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("snapshot", type=pathlib.Path)
    options = parser.parse_args()
    r = report(json.loads(options.snapshot.read_text(encoding="utf-8")))

    d = r["deduplication"]
    print(f"deduplication: {d['advisory_slots']} advisory slots -> {d['unique_findings']} findings "
          f"({d['repeats_removed']} repeats removed)\n")

    def line(row):
        if not row["n"]:
            return f"  {row['label']:<28} (none)"
        mark = "excludes zero" if row.get("excludes_zero") else "INCLUDES ZERO"
        return (f"  {row['label']:<28} n={row['n']:<4} projects={row['projects']:<3} "
                f"{row['mean_gap']:+.2f} bands  95% [{row['lo95']:+.2f},{row['hi95']:+.2f}]  {mark}")

    print("pooled and by bucket, intervals clustered over projects:")
    print(line(r["pooled"]))
    for b in r["buckets"]:
        print(line(b))

    print(f"\nper class, only where n >= {r['min_per_class']} (indicative, not a lookup table):")
    for c in r["per_class_indicative"]:
        print(line(c))
    thin = r["per_class_too_thin"]
    print(f"\n  {len(thin)} classes too thin to report: "
          + ", ".join(f"{t['label']}(n={t['n']})" for t in thin[:10]) + ("..." if len(thin) > 10 else ""))

    print("\nleave-one-project-out on the pooled figure:")
    for row in r["leave_one_project_out"]:
        print(f"  without {row['dropped']:<26} (-{row['dropped_n']:<3}) n={row['remaining_n']:<4} {row['mean_gap']:+.2f}")

    rep = r["representativeness"]
    print(f"\nhow representative the slice is: {rep['slice_size']} findings = "
          f"{rep['slice_share_of_population_pct']:.2f}% of {rep['population']:,} disclosed")
    print("  class                      slice%   population%")
    for row in rep["classes"][:6]:
        print(f"  {row['bug_class']:<26} {row['slice_pct']:5.1f}%   {row['population_pct']:5.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
