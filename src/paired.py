#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The paired comparison: on findings rated by all three parties, is the model
better or worse calibrated to the maintainer than the human triage firm is?

Comparing Claude-vs-maintainer (n=163) against firm-vs-maintainer (n=118) would
be comparing two different, overlapping samples, and any difference could come
from the sample rather than the rater. This restricts both to the findings where
all three severities exist, so the maintainer's rating is held fixed and only
the finder changes. The difference is then tested by a paired bootstrap over
findings, which is the unit that was sampled.
"""
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import stats  # noqa: E402

I = stats.INDEX


def triples(document, with_date=False):
    """Findings where Claude, the firm and the maintainer all assigned a band."""
    out = []
    for p in document["severity_pairs"]:
        c, v, m = I.get(p.get("claude_sev")), I.get(p.get("vendor_sev")), I.get(p.get("maintainer_sev"))
        if None not in (c, v, m):
            out.append((c, v, m, p.get("discovered_on")) if with_date else (c, v, m))
    return out


def clustered(document, seed=20261009, draws=10000):
    """The same comparison with intervals that resample discovery dates, not findings.

    These findings arrive in batches: 22 discovery dates carry the 118 triples and
    the largest supplies 37% of them. Resampling findings assumes 118 independent
    observations, which is not what the data is. These are the intervals the
    conclusions should be read against; the finding-level ones above are narrower
    than the evidence supports.
    """
    rows = triples(document, with_date=True)
    n = len(rows)
    if not n:
        return {"n": 0}
    groups = {}
    for r in rows:
        groups.setdefault(r[3], []).append(r)
    keys = list(groups)
    generator = random.Random(seed)

    def draw():
        pooled = []
        for _ in range(len(keys)):
            pooled.extend(groups[keys[generator.randrange(len(keys))]])
        return pooled

    acc = {"kappa_difference": [], "gap_difference": [], "claude_gap": [], "vendor_gap": []}
    for _ in range(draws):
        s = draw()
        if len(s) < 8:
            continue
        a, b = stats.kappa([(x[0], x[2]) for x in s]), stats.kappa([(x[1], x[2]) for x in s])
        if a is not None and b is not None:
            acc["kappa_difference"].append(a - b)
        acc["claude_gap"].append(sum(x[0] - x[2] for x in s) / len(s))
        acc["vendor_gap"].append(sum(x[1] - x[2] for x in s) / len(s))
        acc["gap_difference"].append(acc["claude_gap"][-1] - acc["vendor_gap"][-1])

    observed = {
        "kappa_difference": stats.kappa([(c, m) for c, v, m, _ in rows]) - stats.kappa([(v, m) for c, v, m, _ in rows]),
        "gap_difference": sum(c - v for c, v, m, _ in rows) / n,
        "claude_gap": sum(c - m for c, v, m, _ in rows) / n,
        "vendor_gap": sum(v - m for c, v, m, _ in rows) / n,
    }

    out = {"n": n, "clusters": len(keys), "largest_cluster": max(len(g) for g in groups.values())}
    for key, values in acc.items():
        values.sort()
        lo, hi = values[int(0.025 * len(values))], values[int(0.975 * len(values))]
        out[key] = {"observed": observed[key], "lo95": lo, "hi95": hi,
                    "excludes_zero": not (lo <= 0 <= hi)}
    return out


def report(document, draws=10000, seed=20261009):
    """The paired comparison as data, for inclusion in the full audit report."""
    rows = triples(document)
    n = len(rows)
    if n == 0:
        return {"n": 0}

    views = {"claude": [(c, m) for c, v, m in rows], "vendor": [(v, m) for c, v, m in rows]}
    labels = {"claude": "Claude vs maintainer", "vendor": "Triage firm vs maintainer"}
    out = {"n": n}
    for who, obs in views.items():
        s = stats.summarise(obs)
        ci = stats.bootstrap(obs, stats.kappa, draws=draws, seed=seed) or {}
        out[who] = {
            "label": labels[who], "kappa": s["kappa"],
            "kappa_lo95": ci.get("lo95"), "kappa_hi95": ci.get("hi95"),
            "exact_pct": s["exact_pct"], "chance_pct": s["chance_pct"],
            "mean_gap": s["mean_gap"],
            "hotter_pct": s["left_higher_pct"], "cooler_pct": s["left_lower_pct"],
            "confusion": s["confusion"],
        }

    # Resample findings, not ratings: the finding is the sampled unit, and
    # holding it fixed across both finders is what makes this paired.
    generator = random.Random(seed)
    differences = {"kappa": [], "gap": []}
    for _ in range(draws):
        sample = [rows[generator.randrange(n)] for _ in range(n)]
        a, b = stats.kappa([(c, m) for c, v, m in sample]), stats.kappa([(v, m) for c, v, m in sample])
        if a is not None and b is not None:
            differences["kappa"].append(a - b)
        differences["gap"].append(
            sum(c - m for c, v, m in sample) / n - sum(v - m for c, v, m in sample) / n
        )

    for key, name in (("kappa", "kappa_difference"), ("gap", "gap_difference")):
        values = sorted(differences[key])
        lo, hi = values[int(0.025 * len(values))], values[int(0.975 * len(values))]
        observed = (out["claude"]["kappa"] - out["vendor"]["kappa"]) if key == "kappa" \
            else (out["claude"]["mean_gap"] - out["vendor"]["mean_gap"])
        out[name] = {
            "observed": observed, "lo95": lo, "hi95": hi,
            "p_positive": sum(1 for v in values if v > 0) / len(values),
            "verdict": "not distinguishable from zero" if lo <= 0 <= hi else "distinguishable from zero",
        }

    both = stats.summarise([(c, v) for c, v, m in rows])
    out["finders_against_each_other"] = {"kappa": both["kappa"], "exact_pct": both["exact_pct"]}
    out["clustered"] = clustered(document, seed=seed, draws=draws)
    return out


def main():
    document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    rows = triples(document)
    n = len(rows)
    print(f"findings rated by all three parties: n={n}\n")

    claude_m = [(c, m) for c, v, m in rows]
    vendor_m = [(v, m) for c, v, m in rows]

    for label, obs in (("Claude    vs maintainer", claude_m), ("Triage firm vs maintainer", vendor_m)):
        s = stats.summarise(obs)
        ci = stats.bootstrap(obs, stats.kappa) or {}
        print(f"  {label:<26} exact {s['exact_pct']:5.1f}%  chance {s['chance_pct']:5.1f}%  "
              f"kappa {s['kappa']:+.3f} [{ci.get('lo95', 0):+.3f},{ci.get('hi95', 0):+.3f}]  "
              f"mean gap {s['mean_gap']:+.3f}  hotter {s['left_higher_pct']:.1f}% / cooler {s['left_lower_pct']:.1f}%")

    # Paired bootstrap on the difference, resampling findings (not ratings).
    k_claude = stats.kappa(claude_m)
    k_vendor = stats.kappa(vendor_m)
    gap_claude = sum(c - m for c, m in claude_m) / n
    gap_vendor = sum(v - m for v, m in vendor_m) / n
    print(f"\n  observed difference  kappa(Claude) - kappa(firm) = {k_claude - k_vendor:+.3f}")
    print(f"  observed difference  gap(Claude)   - gap(firm)   = {gap_claude - gap_vendor:+.3f}")

    generator = random.Random(20261009)
    d_kappa, d_gap = [], []
    for _ in range(10000):
        sample = [rows[generator.randrange(n)] for _ in range(n)]
        a = stats.kappa([(c, m) for c, v, m in sample])
        b = stats.kappa([(v, m) for c, v, m in sample])
        if a is not None and b is not None:
            d_kappa.append(a - b)
        d_gap.append(sum(c - m for c, v, m in sample) / n - sum(v - m for c, v, m in sample) / n)

    def interval(values, label):
        values.sort()
        lo, hi = values[int(0.025 * len(values))], values[int(0.975 * len(values))]
        crosses = lo <= 0 <= hi
        share = sum(1 for v in values if v > 0) / len(values)
        print(f"  {label}: 95% [{lo:+.3f}, {hi:+.3f}]  "
              f"{'includes 0 -> not distinguishable' if crosses else 'excludes 0 -> distinguishable'}  "
              f"(P(diff>0) = {share:.3f})")

    print()
    interval(d_kappa, "paired bootstrap, kappa difference")
    interval(d_gap, "paired bootstrap, mean-gap difference")

    # How often do the two finders disagree with each other on these findings?
    both = [(c, v) for c, v, m in rows]
    s = stats.summarise(both)
    print(f"\n  and the two finders against each other: exact {s['exact_pct']:.1f}%  kappa {s['kappa']:+.3f}")


if __name__ == "__main__":
    main()
