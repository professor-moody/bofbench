# Release qualification

`release-manifest-0.1.0.json` is the exact decision boundary for the local
BOFBench `0.1.0` release candidate. It binds:

- the five release archive checksums from the clean `0.1.0` build;
- internal catalog gate `catalog-2026.08.23.6` and its 8 operation plus 1 pack
  live/cleanup cells;
- every MinGW and unavailable MSVC static cell; and
- the qualified BOFBench-to-EDR-Lab result, including all six cleanups and
  clone destructions.

Every declared coverage cell is `passed`, `withheld`, or `unavailable`.
Anything omitted from the manifest receives no qualification by implication.

From a suite checkout containing sibling `bofbench-packs-internal` and `edrlab`
repositories, verify the complete boundary with:

```sh
python3 scripts/verify-release-manifest.py --require-clean
```

The verifier checks both current file bytes and the same paths at their bound
historical commits. If the release archives are restored, add
`--artifact-root /path/to/bofbench` to verify their bytes and `SHA256SUMS` too.
Tagging, pushing, and publication are deliberately outside the verifier and
require a separate explicit decision.
