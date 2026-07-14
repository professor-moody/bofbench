# Capability Pack Reference

This page is generated from the resolved `pack.json` contracts. Use `bofbench pack docs --output docs/pack-reference.md` to refresh it.

## `builtin/active-actions`

Execute four observable and reversible lab actions without the discovery output.

- Can do: lab-file-write; lab-registry-write; lab-run-key; lab-process-launch
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `active-cleanup`

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

## `builtin/deep-discovery`

all built-in read-only discovery techniques

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/deep-survey`

Combine bounded process, token, service, TCP endpoint, domain, host, identity, filesystem, network, and registry discovery in one BOF.

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/domain-context`

report local workgroup or domain join context

- Can do: domain-context
- Effects: reaches network; reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/domain-discovery`

Report domain join state and the local join name

- Can do: domain-context
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/filesystem`

report the current Windows temporary directory

- Can do: filesystem
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/full-survey`

Exercise the six core read-only BOFBench capabilities in one native loader run.

- Can do: process; host; identity; filesystem; network; registry
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/host`

report the local computer name

- Can do: host
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/host-discovery`

core process, host, identity, and filesystem context

- Can do: process; host; identity; filesystem
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/host-survey`

Collect process, host, user, and temporary-directory context from the current Windows session.

- Can do: process; host; identity; filesystem
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

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

## `builtin/network`

initialize Winsock and report the local host name

- Can do: network
- Effects: reaches network; reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/network-discovery`

host, Winsock, TCP endpoint, and domain context

- Can do: host; network; tcp-connections; domain-context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/network-inventory`

Report the host name and a bounded set of local TCP endpoints

- Can do: network; tcp-connections
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/network-survey`

Report the Windows computer name and Winsock host name from the current network context.

- Can do: host; network
- Effects: reads data
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/offensive-lab`

deep discovery plus observable reversible action primitives

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context; lab-file-write; lab-registry-write; lab-run-key; lab-process-launch
- Effects: writes state
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `active-cleanup`

## `builtin/offensive-survey`

Combine deep discovery with observable file, registry, and child-process actions for an authorized lab operation.

- Can do: process; host; identity; filesystem; network; registry; process-list; token-context; service-list; tcp-connections; domain-context; lab-file-write; lab-registry-write; lab-run-key; lab-process-launch
- Effects: writes state
- Needs: privilege=user; network=local; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `active-cleanup`

## `builtin/process`

report the current process and thread identifiers

- Can do: process
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/process-discovery`

Enumerate a bounded local process snapshot

- Can do: filtered process discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `process_filter` | `string` | no | `` | case-insensitive process image substring; empty matches all |
| `result_limit` | `int` | no | `25` | maximum matching process rows (1-256) |

## `builtin/process-list`

enumerate a bounded snapshot of local processes

- Can do: process-list
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/process-search`

enumerate local processes with a runtime name filter and result limit

- Can do: process-search
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

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

## `builtin/system-discovery`

process, token, and service enumeration

- Can do: filtered process discovery; token context discovery; service discovery
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `process_filter` | `string` | no | `` | case-insensitive process image substring; empty matches all |
| `result_limit` | `int` | no | `25` | maximum matching process rows (1-256) |

## `builtin/tcp-connections`

inventory a bounded set of local IPv4 TCP endpoints and owning PIDs

- Can do: tcp-connections
- Effects: reaches network; reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

## `builtin/token-context`

report token elevation and integrity context

- Can do: token-context
- Effects: reads data
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

