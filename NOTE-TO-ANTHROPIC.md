To: oss-scanner-questions@anthropic.com
Subject: the threat_model.md example vs what your ledger's maintainers actually do

Hi,

Independent dev, no affiliation. Not a vuln report and I don't need anything
back — just one thing I found in the CVD ledger that you might want before a lot
of projects copy templates/threat_model.md.

Your README asks maintainers good questions about severity. One of them is "are
buffer overflows without demonstrated exploits capped at high?" — that's asking
about a ceiling, and conditioning it on whether an exploit was shown.

The template covers the same ground the other way round:

  any buffer overflow, use-after-free, or double free is high+ at a minimum. If
  the overflow is controlled and may lead to RCE then it should be critical. All
  DoS is medium.

That's a floor, it's unconditional, and the one conditional in it goes up. So
across the two docs a maintainer gets shown how to raise a memory-safety finding
and never how to lower one. The template is the file they copy.

What your ledger says they actually do: 33 findings in those classes carry both
a Claude severity and a maintainer severity, across 14 projects. Maintainers put
24 of 33 below that floor — 20 medium, 4 low. Claude put 5 of 33 below it. Mean
bands 1.18 against 1.94. (I read "buffer overflow" as your four overflow
classes; heap 18, stack 7, use-after-free 6, buffer-overflow 2. Each finding
counted once, since one can sit under a CVE and several GHSAs at the same time.)

It also splits hard by project. libreoffice/core rated all ten of its findings
medium. wireshark and wolfssl are entirely below the floor too. The kernel,
FreeBSD, nginx, nss, dnsmasq and ImageMagick are at or above it, and OpenSSL
rated one critical. So there isn't one convention to put in an example.

Suggestion, costs one edit: have the template ask the way the README already
does, or carry two contrasting conventions instead of one. Either gives
maintainers the downward conditional neither doc currently offers.

Where I could be wrong, before you have to go looking:

- n=33 and concentrated. Drop the two biggest contributors and it's 50% below
  the floor instead of 73%. Shrinks, doesn't vanish.
- It only exists where a maintainer published an advisory, and that subset runs
  about 0.24 bands hotter than findings without one. Not a random sample.
- Could partly be CVSS vs a rubric rather than real disagreement. Can't separate
  those from this data.
- An advisory severity isn't the same artefact as a threat-model severity. I'm
  treating one as evidence about the other, which is an assumption.
- If the floor is deliberate and you want it applied whatever maintainers do,
  then this is just the size of that gap.

I reproduced all ten figures you state in prose first — 83.0%, 97.1%, n=1337,
92.7% TPR, 6157 disclosed, 591 projects, 219 CVEs, 365 GHSAs, 5103 acknowledged,
29439 analysed. All exact, or I wouldn't be sending this. I wrote the analysis
with Claude Code, which seems worth saying given who I'm sending it to; every
number came out of the raw file rather than a model's summary, and two earlier
drafts of this were wrong in ways that caught.

Code, pinned snapshot, one command:

  https://github.com/dziuba0x/cvd-ledger-audit
  python3 -I src/template_check.py data/payload-r35.json

Write-up with the charts: https://claude.ai/artifact/KL79qQTiV39xGiGXcHtB6B

Thanks for publishing the ledger as machine-readable JSON. Almost none of this
would be checkable otherwise.

Alan
