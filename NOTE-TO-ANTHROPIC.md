Subject: OSS Scanner: the threat-model template's severity example sits above how your ledger's maintainers rate those classes

Hello,

I am an independent developer with no affiliation to Anthropic. This is not a
vulnerability report and needs no response. It is one observation about
`templates/threat_model.md` that your own published data supports, and which you
may want before many projects copy that file.

## What I did first

Before reporting anything, I reproduced every figure you state in prose at
red.anthropic.com/2026/cvd from the raw `payload.json`: 83.0% severity agreement,
97.1% within one band, n=1337, the 92.7% true positive rate, 6,157 disclosed, 591
projects, 219 CVEs, 365 GHSAs, 5,103 acknowledged, 29,439 analysed. All ten
reproduce exactly. Code and a pinned, hashed snapshot are linked at the end.

## The observation

`templates/threat_model.md` gives one worked example under "How you rate
severity":

    any buffer overflow, use-after-free, or double free is high+ at a minimum

In the revealed portion of the ledger, 33 findings in exactly those classes carry
both a Claude severity and a maintainer severity, across 14 projects. Counting
each finding once (a finding can appear under a CVE and several GHSAs, which
double-counts if you iterate advisory records):

    maintainer   mean band 1.18    low 4, medium 20, high 8, critical 1
                 below the example's floor: 24 of 33  (73%)

    Claude       mean band 1.94    low 1, medium 4,  high 24, critical 4
                 below the example's floor:  5 of 33  (15%)

The model sits close to the floor the example states. The maintainers in your own
ledger mostly sit below it.

## Why I think it is worth a minute of your time

That file is the one channel a maintainer has for telling the scanner their own
severity convention, and its example is the only severity guidance they see
before writing one. If the example states a floor that most maintainers in your
data do not apply, it anchors them toward the finder's convention in the one
place meant to carry the owner's.

Your data also shows these conventions genuinely differ, which is the more
interesting half:

    libreoffice/core        n=10   all 10 medium
    wireshark/wireshark     n=5    4 medium, 1 low
    wolfssl/wolfssl         n=5    3 medium, 2 low
    torvalds/linux          n=2    both high
    freebsd/freebsd-src     n=2    both high
    openssl/openssl         n=1    critical
    nginx, nss, dnsmasq, imagemagick      high
    opensc, libexpat, libgcrypt, util-linux   below high

Three large C and C++ projects rate memory-safety findings at medium as a matter
of course; the kernel, nginx and OpenSSL do not. A worked example cannot be
neutral between those, so it may be worth not having one. Two contrasting real
conventions, or a prompt to state the maintainer's own, would make it clearer
that the file wants their scale rather than a recommended one.

## What would make me wrong

Stated before you find it:

* n=33 across 14 projects, and concentrated. Dropping the two largest
  contributors leaves n=18 and 50% below the floor, down from 73%: the effect
  attenuates but does not vanish.
* The slice is self-selected. A maintainer severity exists only where a
  maintainer published an advisory, and that subset runs about 0.24 bands hotter
  overall than findings without one, so it is not a random sample of your corpus.
* Maintainers commonly score with CVSS while a rubric need not. Part of the gap
  could be the instrument rather than the judgement, and this data cannot
  separate the two.
* Severity bands are ordinal. I report counts above and below one threshold
  rather than averaging distances, because CVSS band widths are not equal.
* It is possible you intend the example as a floor your pipeline should apply
  regardless of maintainer practice. If so, this observation is simply the size
  of that deliberate gap.

## Reproducing it

    git clone <repo>
    python3 src/fetch.py                             # pins and hashes a snapshot
    python3 -I src/template_check.py data/payload-r35.json

Standard library only, no dependencies, offline after the fetch. The repository
also contains the full audit, including two errors of my own that I found and
corrected the same way: a per-class breakdown that double-counted advisory
records, and intervals that assumed findings were independent when 44.2% of the
paired set shares one discovery date.

Thank you for publishing the ledger in a machine-readable form. Very little of
this would be checkable otherwise.
