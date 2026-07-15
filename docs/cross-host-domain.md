# Cross-Host and Domain Topologies

BOFBench separates static capability readiness from live environment claims. Every pack can be built, analyzed, and exported before a second host exists. Cross-host and domain claims require named profiles and completed runtime receipts from the real target roles.

## Register the hosts

```bash
bofbench lab add devbox --provider existing --transport ssh --host bofbench-winvm
bofbench lab add dedicated --provider existing --transport ssh --host 10.0.0.50
bofbench lab add domain-member --provider existing --transport winrm --host 10.0.0.60
bofbench lab add domain-dc --provider existing --transport winrm --host 10.0.0.10
```

Credentials remain in the SSH agent, identity-file path, profile-specific WinRM environment variable, or an un-echoed prompt.

## Standalone cross-host proof

```bash
bofbench lab topology add dedicated-standalone \
  --execution devbox --target dedicated

bofbench lab topology status dedicated-standalone

bofbench pack prove internal/remote-file-read \
  --via lab --topology dedicated-standalone
```

Use the standalone topology to prove SMB, RPC, SCM, Task Scheduler, Remote Registry, WMI, DCOM, staging, execution, and exact cleanup against the target profile. Verification runs independently on the target role.

## Explicit alternate credentials

Remote packs accept the same bounded new-credentials context:

```bash
bofbench run bofs/remote-registry --via lab --topology dedicated-domain \
  --arg auth_mode=new_credentials \
  --arg domain=LAB \
  --arg username=@env:BOFBENCH_TARGET_USER \
  --arg password=@prompt \
  --arg hive=HKLM \
  --arg key_path='Software\BOFBench' \
  --arg value_name="BOFBench-$RUN_ID"
```

BOFBench creates a `LOGON_NETCREDENTIALS_ONLY` token for the named remote operation, impersonates only around that operation, always reverts, and redacts the username/password values from receipts and proof reports.

## Domain proof

```bash
bofbench lab topology add dedicated-domain \
  --execution devbox \
  --target domain-member \
  --domain-controller domain-dc

bofbench pack prove builtin/domain-controller-inventory \
  --via lab --topology dedicated-domain
bofbench pack prove builtin/ldap-account-inventory \
  --via lab --topology dedicated-domain
bofbench pack prove internal/ldap-acl-read \
  --via lab --topology dedicated-domain
```

The domain packs cover bounded controller, account, SPN, delegation, trust, and ACL discovery. Stateful remote operations target the member profile, never the domain controller. BOFBench does not scan hosts, propagate, disable security controls, or reuse credentials beyond the operator-supplied target.

## Teardown standard

Finish each live lane by removing the disposable target and checking the role that owned each effect:

```bash
bofbench lab target remove --lab dedicated
bofbench lab verify clean --lab dedicated
```

A live lane is complete only when its tasks are completed, output is complete, cleanup companions passed, and independent checks show no BOFBench processes, files, services, tasks, registry values, backups, or Remote Registry configuration drift.
