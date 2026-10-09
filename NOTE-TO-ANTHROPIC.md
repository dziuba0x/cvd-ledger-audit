Subject: OSS Scanner: neither worked example gives a maintainer a way down, and most of your ledger's maintainers take one

Hello,

I am an independent developer with no affiliation to Anthropic. This is not a
vulnerability report and needs no response. It is one observation about the
severity guidance in OSS Scanner, supported by your own published ledger, which
you may want before many projects copy `templates/threat_model.md`.

## What I did first

Before reporting anything I reproduced every figure you state in prose at
red.anthropic.com/2026/cvd from the raw `payload.json`: 83.0% severity agreement,
97.1% within one band, n=1337, the 92.7% true positive rate, 6,157 disclosed, 591
projects, 219 CVEs, 365 GHSAs, 5,103 acknowledged, 29,439 analysed. All ten
reproduce exactly. Code and a pinned, hashed snapshot are linked at the end.

## The two worked examples point different ways

The README asks the maintainer a set of questions, and they are good ones:

    do you consider post-auth SQLi high or critical? are buffer overflows
    without demonstrated exploits capped at high? when is stored XSS medium,
    high, and critical?

                                                    — README.md, line 53

That middle question asks about a ceiling, and conditions it on whether an
exploit was demonstrated. The template answers the same ground differently:

    any buffer overflow, use-after-free, or double free is high+ at a minimum.
    If the overflow is controlled and may lead to RCE then it should be
    critical. All DoS is medium.

                                 — templates/threat_model.md, "How you rate severity"

That is a floor, it is unconditional, and its one conditional escalates. Between
the two documents a maintainer is shown how to move a memory-safety finding up,
and never how to move one down.

## What your ledger shows maintainers actually do

In the revealed portion of the ledger, 33 findings in those classes carry both a
Claude severity and a maintainer severity, across 14 projects. I read "buffer
overflow" as the ledger's four overflow classes; of the six classes that reading
covers, four appear in the data — heap-buffer-overflow 18, stack-buffer-overflow
7, use-after-free 6, buffer-overflow 2 — and global-buffer-overflow and
double-free have no finding with both severities. Each finding is counted once,
since one can appear under a CVE and several GHSAs at the same time:

    maintainer   mean band 1.18    low 4, medium 20, high 8, critical 1
                 below the template's floor: 24 of 33  (73%)

    Claude       mean band 1.94    low 1, medium 4,  high 24, critical 4
                 below it:          5 of 33  (15%)

Nearly three quarters of the maintainer ratings sit below the floor the template
states. The model sits close to it.

And the conventions differ sharply between projects, which is the part I found
most interesting:

    libreoffice/core        n=10   all 10 medium            0 of 10 at the floor
    wireshark/wireshark     n=5    4 medium, 1 low          0 of 5
    wolfssl/wolfssl         n=5    3 medium, 2 low          0 of 5
    torvalds/linux          n=2    both high                2 of 2
    freebsd/freebsd-src     n=2    both high                2 of 2
    openssl/openssl         n=1    critical                 1 of 1
    nginx, nss, dnsmasq, imagemagick        at or above the floor
    opensc, libexpat, libgcrypt, util-linux below it

Three large C and C++ projects rate memory-safety findings at medium as a matter
of course; the kernel, nginx and OpenSSL do not.

## The suggestion, which costs one edit

The README already has the better instinct: it asks the maintainer what their
convention is, including about capping. The template's example states one
instead, and it is the example a maintainer copies. Having it ask rather than
answer — or carry two contrasting conventions rather than one — would make it
clearer that the file wants the maintainer's scale and not a recommended one.
It would also give them the downward conditional neither document currently
offers, which is the one 73% of your ledger's maintainers apply.

## What would make me wrong

Stated here rather than left for you to find:

* n=33 across 14 projects, and concentrated. Dropping the two largest
  contributors leaves n=18 and 50% below the floor, down from 73%: the effect
  attenuates but does not vanish.
* The slice is self-selected. A maintainer severity exists only where a
  maintainer published an advisory, and that subset runs about 0.24 bands hotter
  than findings without one, so it is not a random sample of your corpus.
* Maintainers commonly score with CVSS while a rubric need not. Part of this
  could be the instrument rather than the judgement, and the data cannot
  separate the two.
* Severity bands are ordinal, so I report counts above and below one threshold
  rather than averaging distances; CVSS band widths are not equal.
* The template's example may be deliberate guidance you want applied whatever
  maintainers do. If so, this is simply the size of that intended gap.
* A maintainer's published advisory severity and the severity they would write
  in a threat model need not be the same thing. I am treating the first as
  evidence about the second, which is an assumption, not a measurement.

## Reproducing it

    python3 src/fetch.py                             # pins and hashes a snapshot
    python3 -I src/template_check.py data/payload-r35.json

Standard library only, no dependencies, offline after the fetch. The same
repository holds the full audit, including two errors of mine that I found and
corrected the same way: a per-class breakdown that double-counted advisory
records, and intervals that assumed findings were independent when 44.2% of the
paired set shares a single discovery date.

Thank you for publishing the ledger in a machine-readable form. Almost none of
this would be checkable otherwise.
