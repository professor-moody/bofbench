# Run Public Host and Process Capabilities

## Objective

Compose a read-only project that demonstrates bounded discovery, selected process access, module exports, account policy, and network-neighbor state.

## Compose and inspect

```bash
bofbench new host-review --pack \
  process-tree,process-access-check,module-export-inventory,local-account-policy-inventory,network-neighbor-inventory
bofbench pack show process-access-check
bofbench build bofs/host-review --arch x64
bofbench analyze bofs/host-review
```

Analysis should report only read/discovery effects. `process-access-check` attempts requested access but does not modify the selected process.

## Select runtime values

Use a PID and module appropriate to the authorized lab:

```bash
bofbench run bofs/host-review --via lab --lab devbox \
  --arg root_pid=0 \
  --arg target_pid=<PID> \
  --arg access_mask=0 \
  --arg module_filter=kernel32.dll \
  --arg family=0 \
  --arg state_filter=0 \
  --arg result_limit=25
```

Representative structured lines:

```text
[process-access-check] target_pid=<PID> right=query mask=0x00001000 granted=1 error=0
[module-export-inventory] status=complete target_pid=<PID> module=kernel32.dll base=<BASE> shown=25 limit=25
[local-account-policy-inventory] lockout_duration=600 lockout_window=600 lockout_threshold=10
[network-neighbor-inventory] address=<IP> family=ipv4 interface=<INDEX> state=<STATE>
```

## Variations

- Set a nonzero `access_mask` to test that exact Windows process access mask.
- Supply `module_base` when module name selection is ambiguous.
- Set `family=4` or `family=6` to restrict neighbors.
- Lower `result_limit` for compact C2 output.
- Run the same x86 project to compare architecture behavior.

## Evidence

Open `runs/<id>/result.json` and confirm profile, remote computer, object hash, typed values, output, timeout, and exit state. Rerun analysis to attach observed output to that hash.

## Recovery

- `granted=0`: inspect the returned Windows error and current token; this is an operation result, not loader incompatibility.
- zero exports: choose a DLL with exports or select its exact base.
- empty neighbor table: broaden family/state filters or confirm the interface has neighbors.
