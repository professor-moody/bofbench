# EDR Lab bundles

Export one exact x64 BOF for independent product assessment:

```text
bofbench export bofs/portable-survey --for edrlab
```

The owner-only output contains:

- the exact COFF object;
- the x64 native BOFBench loader;
- a fixed PowerShell completion wrapper;
- the packed typed argument bytes in the exact loader argv;
- a run-ID-bound completion effect and cleanup contract; and
- source, object, loader, argument, and replay identities.

The output schema is `windows.artifact-bundle/v1`. The fixed wrapper writes the
effect only when the native loader returns a valid `pass` result. It does not
change BOF arguments or infer a successful external security effect.

An operator may attach selected ReverseLab observations:

```text
bofbench export bofs/portable-survey --for edrlab \
  --guidance guidance/windows-build-guidance.json \
  --guidance-observation abi-runtime-1
```

The exporter verifies the guidance schema and selected IDs, hashes the exact
file, and copies it owner-only. It does not alter the BOF, loader, arguments,
effect, or cleanup automatically.

```text
edrlab artifact export/portable-survey-edrlab/windows-artifact-bundle.json \
  --target-set targets/private/artifact-set-v2.yml \
  --unscored
```

BOFBench does not import EDR Lab and cannot label the run prevented, alerted,
visible, or stealthy. EDR Lab validates the portable bundle and owns those
conclusions.
