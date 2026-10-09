# Severity Gap Audit

An independent reproduction of the public coordinated-disclosure ledger that Anthropic
publishes at [red.anthropic.com/2026/cvd](https://red.anthropic.com/2026/cvd/), plus the
figures that ledger supports but the write-up does not report.

Not affiliated with Anthropic. Public data only. No vulnerability information is used,
derived or republished here: the analysis runs entirely on severity bands, counts and
hashes.

## The result in four lines

1. **All ten published figures reproduce exactly** from the raw ledger — 83.0% severity
   agreement, 97.1% within one band, n=1337, 92.7% true positive rate, and the rest.
2. **That 83% sits on a 51.6% chance baseline.** Both raters answer *high* most of the
   time. Chance-corrected, Cohen's kappa is 0.649 — a good result, not a near-perfect one.
3. **Against the maintainer, both finders fall to chance.** On the 118 findings rated by
   the model, the triage firm *and* the maintainer, kappa is 0.035 and 0.030; both 95%
   intervals include zero. Paired, the difference between them is 0.004 [-0.069, +0.075]:
   **not distinguishable**.
4. **So the inflation belongs to the finder's seat, not to the model.** The two finders
   agree with each other (kappa 0.578, same band 85.6% of the time) and both sit above the
   maintainer — the model 0.64 bands hot, the human firm 0.54. The only difference that
   survives the paired test is magnitude: the model runs 0.093 bands hotter [+0.025,
   +0.161].

A practical corollary for anyone enrolled in OSS Scanner: expect the band on an unreviewed
report to read roughly half a band to two thirds of a band above what you would assign
yourself. That is a calibration note, not a complaint.

## Run it

Python 3, standard library only, no dependencies. Offline after the fetch.

```
python3 src/fetch.py                            # pin a snapshot and hash the bytes
python3 -I src/audit.py data/payload-r35.json   # reproduce, extend, audit
python3 -I src/paired.py data/payload-r35.json  # the three-way paired test
```

`audit.py` **exits non-zero if any published figure stops reproducing**. If Anthropic
revises the ledger and a headline moves, the run fails loudly instead of quietly reporting
new numbers against a stale anchor. `--json out/audit.json` writes the full report.

`-I` runs Python in isolated mode, so nothing on `PYTHONPATH` or in the working directory
can shadow a standard-library module — the ledger is downloaded data and sits next to the
code that reads it.

## What is in here

| Path | What it does |
|---|---|
| `src/fetch.py` | Fetches the ledger, writes `data/payload-r<N>.json` and a SHA3-512 sidecar |
| `src/stats.py` | Cohen's kappa, quadratic-weighted kappa, percentile bootstrap. Fixed seed |
| `src/paired.py` | The three-way comparison on findings all three parties rated |
| `src/audit.py` | Reproduce, extend, and reconcile every aggregate against the per-entry rows |
| `out/report.html` | The written report, with the charts |

## On the ledger's verifiability

The ledger commits 6,597 entries, each with a distinct 512-bit hash, and unseals
per-finding detail only at the `revealed` tier — 237 entries, or 3.6%. The hashes commit
to content no outsider can see, so they cannot be recomputed by design, and the published
aggregates cannot be reconciled against the per-entry rows.

Reconciling them anyway is still worth the effort, because it separates the gaps the
sealing design predicts from the gaps it does not. Seven of ten reconcile or are explained
by sealing. Three are not, and all three are small: disclosed is 3 above the per-entry
flag, the withdrawn flag is 3 below the withdrawn status, and revealed is 2 below the
revealed tier. All three point the way a snapshot taken mid-computation would — the
aggregates are stamped 19:47:20Z while the analysis window runs to the end of that day.
Most likely bookkeeping. Confirming it needs one line from someone who can see the
pipeline.

One field is worth naming on its own: `patch_acceptance` reports `cited: 0, informed: 0,
near_verbatim: 0` over `total_with_proposed_patch: 2`. Whether maintainers take the patches
these models propose is, on this evidence, not yet measured.

## Limits

The central claim rests on 118 findings. In the order that matters:

- **The maintainer severity is not a random sample.** It exists only where a maintainer
  published an advisory, which selects for projects with a formal security process.
- **Scoring frameworks may differ.** Maintainers commonly use CVSS; a finder may work from
  a rubric. Part of a half-band gap could be the instrument rather than the judgement, and
  this dataset cannot separate the two. It is the biggest threat to the reading above.
- **Sample size.** 118 for the three-way test, 163 for Claude against maintainers. Every
  interval is wide and is reported rather than smoothed.
- **Coverage.** `severity_pairs` covers 1,382 of 6,157 disclosed findings (22.4%), and only
  those a firm reviewed, which selects toward the severe.
- **One quoted input.** The 6,123 reviewed denominator for the true positive rate appears
  in prose, not in the data.

What this is *not*: evidence that findings are invalid. Anthropic puts the true positive
rate at 92.7%, and this audit reproduces that. Severity banding and validity are different
questions; only the first is in scope.

## Licence

Apache-2.0. The ledger itself is Anthropic's; this repository contains only analysis code
and a pinned snapshot for reproducibility.
