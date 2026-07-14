# Run Through Cobalt Strike

BOFBench supports export for manual use and opt-in live execution through the licensed headless `agscript` client.

## Export an Aggressor package

```bash
bofbench export bofs/portable-survey --for cobaltstrike \
  --args z:lsass i:5
bofbench export verify export/portable-survey-cobaltstrike.zip
```

The package contains the object, generated `.cna`, named argument contract, capability analysis, manifest, operator instructions, and file hashes. The script uses `bof_pack` and `beacon_inline_execute`.

## Live execution

Set connection details outside the project:

```bash
export BOFBENCH_CS_HOST=teamserver.example
export BOFBENCH_CS_PORT=50050
export BOFBENCH_CS_USER=operator
export BOFBENCH_CS_PASSWORD='...'
export BOFBENCH_CS_BEACON=12345678
export BOFBENCH_CS_AGSCRIPT=/opt/cobaltstrike/agscript
```

Then run:

```bash
bofbench run bofs/portable-survey --via cobaltstrike \
  --arg process_filter=lsass \
  --arg result_limit=5
```

BOFBench creates a mode-0600 ephemeral Aggressor script, waits for the headless client, packs typed values, submits the BOF to the selected Beacon, captures console output, and writes a receipt without the password.

Licensed live tests remain opt-in and outside public CI.
