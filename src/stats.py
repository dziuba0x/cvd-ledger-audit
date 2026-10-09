#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Agreement statistics for ordinal severity bands. Standard library only.

Severity is ordinal (low < medium < high < critical), not nominal, and the
marginal distribution is heavily skewed toward `high`. Both facts matter:

* Raw percent agreement flatters a skewed pair of raters, because two raters who
  both answer `high` most of the time agree often by construction. `kappa`
  subtracts that baseline.
* Nominal kappa treats a low/critical disagreement as no worse than a
  high/critical one. `quadratic_kappa` weights a disagreement by the square of
  the distance between bands, which is the convention for ordinal scales.
* With n in the low hundreds a point estimate alone says little, so every figure
  here comes with a bootstrap interval from `bootstrap`.
"""
import random

BANDS = ("low", "medium", "high", "critical")
INDEX = {band: position for position, band in enumerate(BANDS)}


def pairs(records, left, right):
    """Return [(i, j)] for records where both fields hold a known band."""
    found = []
    for record in records:
        a, b = INDEX.get(record.get(left)), INDEX.get(record.get(right))
        if a is not None and b is not None:
            found.append((a, b))
    return found


def _marginals(observations):
    """Return (row counts, column counts, n) for a list of (i, j)."""
    rows = [0] * len(BANDS)
    columns = [0] * len(BANDS)
    for a, b in observations:
        rows[a] += 1
        columns[b] += 1
    return rows, columns, len(observations)


def kappa(observations, weighted=False):
    """Cohen's kappa, or quadratic-weighted kappa when `weighted` is set.

    Returns None when it is undefined: no observations, or a pair of raters so
    degenerate that chance agreement is already 1.
    """
    rows, columns, n = _marginals(observations)
    if n == 0:
        return None
    size = len(BANDS)
    if weighted:
        cost = lambda i, j: ((i - j) ** 2) / ((size - 1) ** 2)  # noqa: E731
    else:
        cost = lambda i, j: 0.0 if i == j else 1.0              # noqa: E731

    table = {}
    for a, b in observations:
        table[(a, b)] = table.get((a, b), 0) + 1

    observed = sum(cost(i, j) * table.get((i, j), 0) for i in range(size) for j in range(size)) / n
    expected = sum(cost(i, j) * rows[i] * columns[j] for i in range(size) for j in range(size)) / (n * n)
    if expected == 0:
        return None
    return 1.0 - observed / expected


def summarise(observations):
    """Return every figure this audit quotes for one pair of raters."""
    rows, columns, n = _marginals(observations)
    if n == 0:
        return {"n": 0}
    exact = sum(1 for a, b in observations if a == b)
    chance = sum(rows[k] * columns[k] for k in range(len(BANDS))) / (n * n)
    higher = sum(1 for a, b in observations if a > b)
    lower = sum(1 for a, b in observations if a < b)
    table = {}
    for a, b in observations:
        table[(a, b)] = table.get((a, b), 0) + 1
    return {
        "n": n,
        "exact_pct": 100 * exact / n,
        "within_one_pct": 100 * sum(1 for a, b in observations if abs(a - b) <= 1) / n,
        "chance_pct": 100 * chance,
        "kappa": kappa(observations),
        "quadratic_kappa": kappa(observations, weighted=True),
        # Positive mean_gap means the left-hand rater sits above the right-hand one.
        "mean_gap": sum(a - b for a, b in observations) / n,
        "left_higher_pct": 100 * higher / n,
        "left_lower_pct": 100 * lower / n,
        "inflation_ratio": (higher / lower) if lower else None,
        "confusion": [[table.get((i, j), 0) for j in range(len(BANDS))] for i in range(len(BANDS))],
        "row_marginals": rows,
        "column_marginals": columns,
    }


def bootstrap(observations, statistic, draws=5000, seed=20261009):
    """Percentile bootstrap interval for `statistic` over the pair list.

    The seed is fixed so a reader re-running this gets the identical interval;
    an audit whose numbers move between runs cannot be checked.
    """
    n = len(observations)
    if n == 0:
        return None
    generator = random.Random(seed)
    values = []
    for _ in range(draws):
        sample = [observations[generator.randrange(n)] for _ in range(n)]
        value = statistic(sample)
        if value is not None:
            values.append(value)
    if not values:
        return None
    values.sort()
    at = lambda q: values[min(len(values) - 1, max(0, int(q * len(values))))]  # noqa: E731
    return {"lo95": at(0.025), "hi95": at(0.975), "draws_used": len(values)}
