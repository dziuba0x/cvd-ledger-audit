#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch and pin a snapshot of Anthropic's public CVD ledger.

    src/fetch.py [--out data/]

The ledger is published as one JSON document at
https://red.anthropic.com/2026/cvd/data/payload.json and carries a `revision`
counter plus an `as_of` timestamp. Every snapshot is written to
data/payload-r<revision>.json and hashed, so an analysis can always name the
exact bytes it ran on. Nothing here parses the ledger; that is audit.py's job.

Standard library only, by design: an audit that needs a dependency tree is an
audit nobody re-runs.
"""
import argparse
import hashlib
import json
import pathlib
import sys
import urllib.request

URL = "https://red.anthropic.com/2026/cvd/data/payload.json"
UA = "glasswing-ledger-audit/1.0 (independent reproduction of published figures)"


def fetch(url=URL, timeout=60):
    """Return the raw bytes of the ledger. Raises on any non-200."""
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"{url} returned HTTP {response.status}")
        return response.read()


def pin(raw, directory):
    """Write `raw` to <directory>/payload-r<revision>.json. Return (path, digest, revision)."""
    document = json.loads(raw)
    revision = document.get("revision", "unknown")
    digest = hashlib.sha3_512(raw).hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"payload-r{revision}.json"
    path.write_bytes(raw)
    # The sidecar is what a reader checks: it names the bytes, not the analysis.
    (directory / f"payload-r{revision}.sha3-512").write_text(
        f"{digest}  payload-r{revision}.json\n", encoding="utf-8"
    )
    return path, digest, revision


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent / "data")
    parser.add_argument("--url", default=URL)
    options = parser.parse_args()

    try:
        raw = fetch(options.url)
    except Exception as error:                      # noqa: BLE001 - the operator wants the reason, not a traceback
        sys.exit(f"could not fetch {options.url}: {type(error).__name__}: {error}")

    path, digest, revision = pin(raw, options.out)
    document = json.loads(raw)
    print(f"revision      {revision}")
    print(f"as_of         {document.get('as_of')}")
    print(f"bytes         {len(raw):,}")
    print(f"sha3-512      {digest}")
    print(f"manifest_sha3 {document.get('manifest_sha3', '')[:32]}...  (as published, inside the document)")
    print(f"written       {path}")


if __name__ == "__main__":
    main()
