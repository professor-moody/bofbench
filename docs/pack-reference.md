# Capability Pack Reference

This page is generated from resolved `pack.json` contracts. Use `bofbench pack docs --catalog-name builtin --output docs/pack-reference.md` for the public catalog, or select another configured catalog explicitly.

## `builtin/active-actions`

Execute four observable and reversible lab actions without the discovery output.

- Can do: lab-file-write; lab-registry-write; lab-run-key; lab-process-launch
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `active-cleanup`
- Analyzer signatures: `run_key_persistence`

## `builtin/active-cleanup`

Remove only the known temporary-file and registry artifacts created by the active offensive lab survey.

- Can do: lab-cleanup
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/active-lab`

observable file, registry, inert Run-key persistence, and child-process state changes

- Can do: lab-file-write; lab-registry-write; lab-run-key; lab-process-launch
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `active-cleanup`
- Analyzer signatures: `run_key_persistence`

## `builtin/alpc-port-inventory`

enumerate bounded ALPC and LPC port names from an Object Manager directory

- Can do: bounded ALPC and LPC port-name discovery in an exact Object Manager directory
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `alpc_port_inventory`
- Live proofs: rpc-control (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `directory` | `wstring` | no | no | `\RPC Control` | exact Object Manager directory |
| `prefix` | `wstring` | no | no | `` | case-insensitive port-name prefix |
| `result_limit` | `int` | no | no | `64` | maximum ports (1-512) |

## `builtin/certificate-store-inventory`

enumerate bounded certificate metadata from one explicit Windows certificate store

- Can do: certificate metadata discovery; private-key availability discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `certificate_store_inventory`
- Live proofs: fixture-certificate (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `scope` | `string` | no | no | `current_user` | current_user or local_machine |
| `store` | `wstring` | no | no | `MY` | certificate store name |
| `subject_filter` | `wstring` | no | no | `` | case-insensitive subject substring; empty matches all |
| `result_limit` | `int` | no | no | `25` | maximum certificate rows (1-256) |

## `builtin/com-registration-inventory`

enumerate bounded COM CLSID registration metadata

- Can do: bounded COM CLSID, ProgID, server, and threading-model inventory
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Stored-output redaction: `server`
- Analyzer signatures: `com_registration_inventory`
- Live proofs: bounded-machine (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `scope` | `string` | no | no | `all` | all, user, or machine |
| `registry_view` | `string` | no | no | `native` | native, 32, or 64 |
| `clsid_filter` | `wstring` | no | no | `` | case-insensitive CLSID substring |
| `result_limit` | `int` | no | no | `64` | maximum registrations (1-512) |

## `builtin/deep-discovery`

all built-in read-only discovery techniques

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `current_process_context`, `host_identity`, `filesystem_context`

## `builtin/deep-survey`

Combine bounded process, token, service, TCP endpoint, domain, host, identity, filesystem, network, and registry discovery in one BOF.

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `current_process_context`, `host_identity`, `filesystem_context`

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `process_filter` | `string` | no | no | `` | case-insensitive process image substring; empty matches all |
| `result_limit` | `int` | no | no | `25` | maximum matching process rows (1-256) |

## `builtin/domain-context`

report local workgroup or domain join context

- Can do: domain-context
- Effects: reaches network; reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/domain-controller-inventory`

Enumerate bounded domain-controller computer accounts and operating-system metadata

- Can do: bounded domain-controller inventory
- Effects: reaches a domain controller; reads directory data
- Needs: privilege=user; network=domain controller; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `domain_controller_inventory`
- Live proofs: domain-topology (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | exact domain controller; topology supplies this when omitted |
| `base_dn` | `string` | no | no | `` | LDAP search base; topology supplies the domain base DN when omitted |
| `filter` | `string` | no | no | `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))` | bounded LDAP filter |
| `attributes` | `string` | no | no | `dNSHostName,operatingSystem,operatingSystemVersion` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/domain-discovery`

Report domain join state and the local join name

- Can do: domain-context
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/domain-trust-inventory`

Enumerate bounded trusted-domain direction, type, and attribute metadata

- Can do: bounded domain trust inventory
- Effects: reaches a domain controller; reads directory data
- Needs: privilege=user; network=domain controller; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `domain_trust_inventory`
- Live proofs: domain-topology (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | exact domain controller; topology supplies this when omitted |
| `base_dn` | `string` | no | no | `` | LDAP search base; topology supplies the domain base DN when omitted |
| `filter` | `string` | no | no | `(objectClass=trustedDomain)` | bounded LDAP filter |
| `attributes` | `string` | no | no | `name,trustDirection,trustType,trustAttributes` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/filesystem`

report the current Windows temporary directory

- Can do: filesystem
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `filesystem_context`

## `builtin/full-survey`

Exercise the six core read-only BOFBench capabilities in one native loader run.

- Can do: process; host; identity; filesystem; network; registry
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `current_process_context`, `host_identity`, `filesystem_context`

## `builtin/host`

report the local computer name

- Can do: host
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `host_identity`

## `builtin/host-discovery`

core process, host, identity, and filesystem context

- Can do: process; host; identity; filesystem
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `current_process_context`, `host_identity`, `filesystem_context`

## `builtin/host-survey`

Collect process, host, user, and temporary-directory context from the current Windows session.

- Can do: process; host; identity; filesystem
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `current_process_context`, `host_identity`, `filesystem_context`

## `builtin/identity`

report the current Windows user name

- Can do: identity
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/identity-discovery`

Report the current account and its token elevation and integrity context

- Can do: identity; token-context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/lab-cleanup`

remove only the known BOFBench temporary-file and registry lab markers

- Can do: lab-cleanup
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/lab-file-write`

create a known BOFBench marker file in the Windows temporary directory

- Can do: lab-file-write
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/lab-process-launch`

launch a bounded child process that creates a second BOFBench lab marker

- Can do: lab-process-launch
- Effects: starts execution; writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/lab-registry-write`

write a known BOFBench marker under the current user's registry hive

- Can do: lab-registry-write
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/lab-run-key`

install an inert current-user Run-key persistence proof for the authorized lab

- Can do: lab-run-key
- Effects: persists; writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `run_key_persistence`

## `builtin/ldap-account-inventory`

Enumerate bounded domain account identity and control metadata

- Can do: bounded LDAP account inventory
- Effects: reaches a domain controller; reads directory data
- Needs: privilege=user; network=domain controller; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `ldap_account_inventory`
- Live proofs: domain-topology (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | exact domain controller; topology supplies this when omitted |
| `base_dn` | `string` | no | no | `` | LDAP search base; topology supplies the domain base DN when omitted |
| `filter` | `string` | no | no | `(&(objectCategory=person)(objectClass=user))` | bounded LDAP filter |
| `attributes` | `string` | no | no | `sAMAccountName,userPrincipalName,userAccountControl` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/ldap-computer-inventory`

Enumerate bounded domain computer identity, operating-system, and account metadata

- Can do: bounded LDAP computer inventory
- Effects: reaches a domain controller; reads directory data
- Needs: privilege=user; network=domain controller; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `ldap_computer_inventory`
- Live proofs: domain-topology (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | exact domain controller; topology supplies this when omitted |
| `base_dn` | `string` | no | no | `` | LDAP search base; topology supplies the domain base DN when omitted |
| `filter` | `string` | no | no | `(objectCategory=computer)` | bounded LDAP filter |
| `attributes` | `string` | no | no | `dNSHostName,operatingSystem,operatingSystemVersion,userAccountControl` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/ldap-delegation-inventory`

Enumerate bounded constrained, resource-based, and unconstrained delegation metadata

- Can do: bounded LDAP delegation inventory
- Effects: reaches a domain controller; reads directory data
- Needs: privilege=user; network=domain controller; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `ldap_delegation_inventory`
- Live proofs: domain-topology (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | exact domain controller; topology supplies this when omitted |
| `base_dn` | `string` | no | no | `` | LDAP search base; topology supplies the domain base DN when omitted |
| `filter` | `string` | no | no | `(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))` | bounded LDAP filter |
| `attributes` | `string` | no | no | `sAMAccountName,userAccountControl,msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/ldap-gpo-inventory`

Enumerate bounded Group Policy object identity, version, and filesystem location metadata

- Can do: bounded LDAP GPO inventory
- Effects: reaches a domain controller; reads directory data
- Needs: privilege=user; network=domain controller; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `ldap_gpo_inventory`
- Live proofs: domain-topology (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | exact domain controller; topology supplies this when omitted |
| `base_dn` | `string` | no | no | `` | LDAP search base; topology supplies the domain base DN when omitted |
| `filter` | `string` | no | no | `(objectClass=groupPolicyContainer)` | bounded LDAP filter |
| `attributes` | `string` | no | no | `displayName,name,versionNumber,gPCFileSysPath` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/ldap-group-inventory`

Enumerate bounded domain group identity, scope, and membership metadata

- Can do: bounded LDAP group inventory
- Effects: reaches a domain controller; reads directory data
- Needs: privilege=user; network=domain controller; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `ldap_group_inventory`
- Live proofs: domain-topology (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | exact domain controller; topology supplies this when omitted |
| `base_dn` | `string` | no | no | `` | LDAP search base; topology supplies the domain base DN when omitted |
| `filter` | `string` | no | no | `(objectCategory=group)` | bounded LDAP filter |
| `attributes` | `string` | no | no | `sAMAccountName,groupType,member` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/ldap-query`

run a bounded LDAP query with an explicit base, filter, and attribute list

- Can do: bounded LDAP directory query; explicit attribute retrieval
- Effects: reads data
- Needs: privilege=user; network=domain; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `ldap_directory_query`

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | domain controller; empty discovers the current domain |
| `base_dn` | `string` | no | no | `` | LDAP base DN; empty derives the current domain |
| `filter` | `string` | no | no | `(objectClass=*)` | LDAP filter |
| `attributes` | `string` | no | no | `distinguishedName` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/ldap-spn-inventory`

Enumerate bounded accounts and their registered service-principal names

- Can do: bounded LDAP SPN inventory
- Effects: reaches a domain controller; reads directory data
- Needs: privilege=user; network=domain controller; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `ldap_spn_inventory`
- Live proofs: domain-topology (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `server` | `string` | no | no | `` | exact domain controller; topology supplies this when omitted |
| `base_dn` | `string` | no | no | `` | LDAP search base; topology supplies the domain base DN when omitted |
| `filter` | `string` | no | no | `(servicePrincipalName=*)` | bounded LDAP filter |
| `attributes` | `string` | no | no | `sAMAccountName,servicePrincipalName` | comma-separated attributes (maximum eight) |
| `result_limit` | `int` | no | no | `25` | maximum directory entries (1-100) |

## `builtin/local-account-policy-inventory`

report local password, lockout, and authentication policy metadata

- Can do: local password policy inventory; local lockout and authentication-role inventory
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `local_account_policy_inventory`
- Live proofs: local-policy (lab, sliver)

## `builtin/mailslot-inventory`

enumerate bounded local mailslot names with an exact prefix filter

- Can do: bounded local mailslot discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `mailslot_inventory`
- Live proofs: target-mailslot (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `prefix` | `wstring` | no | no | `` |  |
| `result_limit` | `int` | no | no | `64` |  |

## `builtin/module-export-inventory`

enumerate bounded exports from one selected process module

- Can do: bounded export inventory for one selected process module
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `module_export_inventory`
- Live proofs: target-module-exports (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | exact process identifier |
| `module_filter` | `string` | no | no | `` | case-insensitive module or export-name substring |
| `module_base` | `string` | no | no | `` | optional exact hexadecimal module base |
| `result_limit` | `int` | no | no | `64` | maximum export rows (1-512) |

## `builtin/module-section-inventory`

enumerate bounded PE sections from one selected process module

- Can do: bounded PE section inventory for one selected process module
- Effects: reads process module metadata; reads process memory
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `module_section_inventory`
- Live proofs: target-module-sections (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | exact process identifier |
| `module_filter` | `string` | no | no | `` | case-insensitive module substring |
| `module_base` | `string` | no | no | `` | optional exact module base |
| `result_limit` | `int` | no | no | `32` | maximum section rows |

## `builtin/named-object-security-inventory`

read owner and DACL metadata for one exact named kernel object

- Can do: owner and DACL metadata for one exact named event, mutex, semaphore, section, or job
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `named_object_security_inventory`
- Live proofs: target-event (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `object_type` | `string` | yes | no | `` | event, mutex, semaphore, section, or job |
| `object_name` | `wstring` | yes | no | `` | exact object name |

## `builtin/named-pipe-inventory`

enumerate bounded named-pipe entries with an optional prefix filter

- Can do: bounded named-pipe discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `named_pipe_inventory`
- Live proofs: bounded (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `prefix` | `string` | no | no | `` | case-insensitive pipe-name prefix; empty matches all |
| `result_limit` | `int` | no | no | `64` | maximum rows (1-512) |

## `builtin/network`

initialize Winsock and report the local host name

- Can do: network
- Effects: reaches network; reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/network-adapter-inventory`

enumerate bounded network adapters, addresses, gateways, and DNS servers

- Can do: bounded network adapter and address inventory; gateway and DNS server discovery
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `network_adapter_inventory`
- Live proofs: bounded-adapters (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `family` | `string` | no | no | `all` | all, ipv4, or ipv6 |
| `interface_filter` | `string` | no | no | `` | adapter or friendly-name substring |
| `result_limit` | `int` | no | no | `32` | maximum adapters (1-256) |

## `builtin/network-discovery`

host, Winsock, TCP endpoint, and domain context

- Can do: host; network; tcp-connections; domain-context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `host_identity`

## `builtin/network-inventory`

Report the host name and a bounded set of local TCP endpoints

- Can do: network; tcp-connections
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/network-neighbor-inventory`

enumerate bounded IPv4 and IPv6 neighbor-cache metadata

- Can do: bounded IPv4 and IPv6 neighbor-cache inventory
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `network_neighbor_inventory`
- Live proofs: bounded-neighbors (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `family` | `string` | no | no | `all` | all, ipv4, or ipv6 |
| `interface_index` | `int` | no | no | `0` | exact interface index; zero matches all |
| `result_limit` | `int` | no | no | `64` | maximum neighbor rows (1-512) |

## `builtin/network-route-inventory`

enumerate bounded IPv4 and IPv6 forwarding routes

- Can do: bounded IPv4 and IPv6 route inventory
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `network_route_inventory`
- Live proofs: bounded-routes (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `family` | `string` | no | no | `all` | all, ipv4, or ipv6 |
| `interface_index` | `int` | no | no | `0` | exact interface index; zero matches all |
| `result_limit` | `int` | no | no | `64` | maximum routes (1-512) |

## `builtin/network-survey`

Report the Windows computer name and Winsock host name from the current network context.

- Can do: host; network
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `host_identity`

## `builtin/object-namespace-inventory`

enumerate bounded entries from one Windows object-manager directory

- Can do: bounded Windows object-manager namespace inventory
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `object_namespace_inventory`
- Live proofs: base-named-objects (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `directory` | `wstring` | no | no | `\BaseNamedObjects` | object-manager directory such as \BaseNamedObjects |
| `prefix` | `string` | no | no | `` | case-insensitive name prefix; empty matches all |
| `result_limit` | `int` | no | no | `64` | maximum objects (1-512) |

## `builtin/offensive-lab`

deep discovery plus observable reversible action primitives

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context; lab-file-write; lab-registry-write; lab-run-key; lab-process-launch
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `active-cleanup`
- Analyzer signatures: `current_process_context`, `host_identity`, `filesystem_context`, `run_key_persistence`

## `builtin/offensive-survey`

Combine deep discovery with observable file, registry, and child-process actions for an authorized lab operation.

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context; lab-file-write; lab-registry-write; lab-run-key; lab-process-launch
- Effects: writes state
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `active-cleanup`
- Analyzer signatures: `current_process_context`, `host_identity`, `filesystem_context`, `run_key_persistence`

## `builtin/process`

report the current process and thread identifiers

- Can do: process
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `current_process_context`

## `builtin/process-access-check`

test requested process access rights against one selected PID

- Can do: selected-process access-right discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_access_check`
- Live proofs: target-standard-rights (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | exact process identifier |
| `access_mask` | `int` | no | no | `0` | exact access mask; zero tests the standard operator rights |

## `builtin/process-discovery`

Enumerate a bounded local process snapshot

- Can do: filtered process discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `process_filter` | `string` | no | no | `` | case-insensitive process image substring; empty matches all |
| `result_limit` | `int` | no | no | `25` | maximum matching process rows (1-256) |

## `builtin/process-handle-detail-inventory`

enumerate bounded handle values, types, names, access, and attributes for one exact process

- Can do: bounded handle value, type, name, access, and attribute inventory for one exact process
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_handle_detail_inventory`
- Live proofs: target-event-handles (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` |  |
| `type_filter` | `string` | no | no | `` |  |
| `name_filter` | `string` | no | no | `` |  |
| `result_limit` | `int` | no | no | `64` |  |

## `builtin/process-handle-type-summary`

summarize bounded process handles by Windows object type

- Can do: bounded per-object-type handle counts for one selected process
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_handle_type_summary`
- Live proofs: target-handles (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | exact process identifier |
| `result_limit` | `int` | no | no | `64` | maximum object types (1-256) |

## `builtin/process-heap-inventory`

enumerate bounded heaps and entries for one selected process

- Can do: bounded heap and heap-entry inventory for one process
- Effects: reads process heap metadata
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_heap_inventory`
- Live proofs: target-heaps (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` |  |
| `result_limit` | `int` | no | no | `64` |  |

## `builtin/process-image-inventory`

enumerate bounded loaded images for one explicitly selected process

- Can do: bounded loaded-image inventory for one selected process; module base, size, and path discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_image_inventory`
- Live proofs: target-images (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | process identifier |
| `module_filter` | `string` | no | no | `` | case-insensitive module-name substring; empty matches all |
| `result_limit` | `int` | no | no | `64` | maximum images (1-512) |

## `builtin/process-job-inventory`

report job-object membership for one explicitly selected process

- Can do: process job-object membership discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_job_inventory`
- Live proofs: target-job (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | process identifier |

## `builtin/process-list`

enumerate a bounded snapshot of local processes

- Can do: process-list
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/process-memory-map`

enumerate bounded committed virtual-memory regions for one explicitly selected process

- Can do: bounded committed-memory region inventory; mapped image and protection discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_memory_map`
- Live proofs: target-map (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | exact process identifier |
| `result_limit` | `int` | no | no | `64` | maximum committed regions (1-512) |

## `builtin/process-mitigation-inventory`

report bounded mitigation-policy flags for one explicitly selected process

- Can do: bounded process mitigation policy inventory; DEP, ASLR, dynamic-code, CFG, signature, and child-process policy discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_mitigation_inventory`
- Live proofs: target-policies (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | exact process identifier |

## `builtin/process-search`

enumerate local processes with a runtime name filter and result limit

- Can do: process-search
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/process-security-inventory`

report owner, group, DACL, inheritance, and security-control metadata for one process

- Can do: process owner, group, DACL, inheritance, and security-control inventory
- Effects: reads process security metadata
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_security_inventory`
- Live proofs: target-security (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` |  |

## `builtin/process-tree`

enumerate a bounded process tree with session and architecture context

- Can do: bounded process tree inventory; process session and architecture context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `process_tree_inventory`
- Live proofs: bounded (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `process_filter` | `string` | no | no | `` | case-insensitive image substring; empty matches all |
| `result_limit` | `int` | no | no | `25` | maximum rows (1-256) |

## `builtin/proxy-configuration-inventory`

report current-user WinHTTP proxy, PAC, bypass, and auto-detection configuration

- Can do: current-user proxy and PAC configuration discovery; proxy auto-detection and bypass discovery
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Stored-output redaction: `proxy`, `bypass`, `auto_config_url`
- Analyzer signatures: `proxy_configuration_inventory`
- Live proofs: current-user (lab, sliver)

## `builtin/registry`

read the Windows product name from the local registry

- Can do: registry
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/registry-query`

Read the local Windows product name from the registry

- Can do: registry
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/registry-survey`

Read Windows product context from HKLM and report the current user.

- Can do: identity; registry
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/remote-host-info`

report bounded workstation and server identity for one explicitly supplied Windows host

- Can do: exact-host workstation identity; exact-host server role and version discovery
- Effects: reaches a supplied host; reads host metadata
- Needs: privilege=user; network=explicit host; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `remote_host_information`
- Live proofs: named-host (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_host` | `wstring` | yes | no | `` | exact Windows host name |

## `builtin/remote-service-inventory`

enumerate a bounded filtered service inventory from one explicitly supplied Windows host

- Can do: bounded exact-host service inventory; remote service state and process discovery
- Effects: reaches a supplied host; reads service metadata
- Needs: privilege=user; network=explicit host; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `remote_service_inventory`
- Live proofs: target-service (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_host` | `wstring` | yes | no | `` | exact Windows host name |
| `name_filter` | `wstring` | no | no | `` | case-insensitive service name or display-name substring |
| `state_filter` | `string` | no | no | `all` | all, running, or stopped |
| `result_limit` | `int` | no | no | `32` | maximum service rows (1-256) |

## `builtin/remote-task-inventory`

enumerate bounded Task Scheduler metadata from one explicitly supplied Windows host

- Can do: bounded exact-host scheduled-task inventory; remote task state and result discovery
- Effects: reaches a supplied host; reads scheduled-task metadata
- Needs: privilege=user; network=explicit host; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `remote_task_inventory`
- Live proofs: named-host (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_host` | `wstring` | yes | no | `` | exact Windows host name |
| `name_filter` | `wstring` | no | no | `` | case-insensitive task-name substring |
| `result_limit` | `int` | no | no | `32` | maximum task rows (1-256) |

## `builtin/rpc-endpoint-inventory`

enumerate bounded local RPC endpoint-mapper registrations

- Can do: bounded local RPC endpoint-mapper inventory
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `rpc_endpoint_inventory`
- Live proofs: bounded-local (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `result_limit` | `int` | no | no | `64` | maximum endpoint rows (1-512) |

## `builtin/security-package-inventory`

enumerate bounded Windows authentication and security-support packages

- Can do: Windows authentication package discovery; SSPI capability inventory
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `security_package_inventory`
- Live proofs: bounded (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `name_filter` | `string` | no | no | `` | case-insensitive package-name substring; empty matches all |
| `result_limit` | `int` | no | no | `25` | maximum package rows (1-128) |

## `builtin/service-discovery`

Enumerate a bounded local Windows service snapshot

- Can do: service-list
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/service-list`

enumerate a bounded set of local Windows services

- Can do: service-list
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/survey`

Collect compact host, identity, token, process, service, network, registry, and domain context

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `current_process_context`, `host_identity`, `filesystem_context`

## `builtin/synchronization-object-state`

query exact named event, mutex, semaphore, or waitable-timer state without changing it

- Can do: non-mutating exact named event, mutex, semaphore, or timer state inspection
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `synchronization_object_state`
- Live proofs: target-mutex (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `object_type` | `string` | yes | no | `` | event, mutex, semaphore, or timer |
| `object_name` | `wstring` | yes | no | `` |  |

## `builtin/system-discovery`

process, token, and service enumeration

- Can do: filtered process discovery; token context discovery; service discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `process_filter` | `string` | no | no | `` | case-insensitive process image substring; empty matches all |
| `result_limit` | `int` | no | no | `25` | maximum matching process rows (1-256) |

## `builtin/tcp-connections`

inventory a bounded set of local IPv4 TCP endpoints and owning PIDs

- Can do: tcp-connections
- Effects: reaches network; reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/thread-inventory`

enumerate bounded thread identifiers and priorities for one process

- Can do: bounded thread inventory for one process
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `thread_inventory`
- Live proofs: target-threads (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | exact process identifier |
| `result_limit` | `int` | no | no | `64` | maximum rows (1-512) |

## `builtin/thread-start-inventory`

enumerate bounded thread start addresses and containing process regions for one selected process

- Can do: bounded thread start-address inventory; thread start region and mapped-image discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `thread_start_inventory`
- Live proofs: target-starts (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | exact process identifier |
| `result_limit` | `int` | no | no | `64` | maximum threads (1-512) |

## `builtin/thread-state-inventory`

enumerate bounded thread scheduling and execution-time state for one selected process

- Can do: bounded thread scheduling-state inventory; thread priority and execution-time discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `thread_state_inventory`
- Live proofs: target-thread-state (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | no | `` | process identifier |
| `result_limit` | `int` | no | no | `64` | maximum threads (1-512) |

## `builtin/thread-wait-chain-inventory`

inspect bounded Windows wait chains for an exact process or thread

- Can do: bounded Windows wait-chain traversal for one exact process or thread
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Analyzer signatures: `thread_wait_chain_inventory`
- Live proofs: target-waits (lab, sliver)

| Argument | Type | Required | Sensitive | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `target_pid` | `int` | no | no | `0` | exact process identifier; required when target_tid is zero |
| `target_tid` | `int` | no | no | `0` | exact thread identifier; zero enumerates threads in target_pid |
| `result_limit` | `int` | no | no | `64` | maximum wait-chain nodes (1-512) |

## `builtin/token-context`

report token elevation and integrity context

- Can do: token-context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
