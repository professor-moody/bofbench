# Capability Pack Reference

This page is generated from the resolved `pack.json` contracts. Use `bofbench pack docs --output docs/pack-reference.md` to refresh it.

## `bofbench-packs-internal/apc-inject`

Write operator-supplied bytes into one selected process and queue them to one selected thread

- Can do: APC process injection; remote process memory write; queued execution
- Effects: accesses another process; writes process memory; starts execution
- Needs: privilege=process and thread access rights for the supplied IDs; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | `` | exact target process ID |
| `target_tid` | `int` | yes | `` | exact alertable target thread ID |
| `payload` | `bytes` | yes | `` | operator-supplied payload bytes |

## `bofbench-packs-internal/credential-list`

Enumerate bounded Credential Manager metadata for the current security context

- Can do: Credential Manager enumeration
- Effects: reads credential metadata
- Needs: privilege=current-user Credential Manager access; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `filter` | `wstring` | yes | `` |  |
| `result_limit` | `int` | no | `25` |  |

## `bofbench-packs-internal/credential-read`

Read one exact Credential Manager entry and print no more than the supplied byte limit

- Can do: targeted Credential Manager secret read
- Effects: accesses credential material
- Needs: privilege=access to the exact current-context credential; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_name` | `wstring` | yes | `` |  |
| `max_bytes` | `int` | no | `128` |  |

## `bofbench-packs-internal/dpapi-unprotect-file`

Read one explicit DPAPI blob and print a strictly bounded portion of recovered material

- Can do: DPAPI unprotect; protected file material access
- Effects: reads a file; accesses protected material
- Needs: privilege=matching user or machine DPAPI context; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `blob_path` | `wstring` | yes | `` |  |
| `max_bytes` | `int` | no | `128` |  |

## `bofbench-packs-internal/driver-inventory`

Enumerate a bounded list of loaded kernel driver base addresses and names

- Can do: loaded driver discovery
- Effects: reads system metadata
- Needs: privilege=user; some driver names may require elevation; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `result_limit` | `int` | no | `64` |  |

## `bofbench-packs-internal/file-collect`

Read an exact path up to an operator-supplied byte limit and return the bytes

- Can do: file collection
- Effects: reads data
- Needs: privilege=read access to the selected path; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `path` | `wstring` | yes | `` |  |
| `max_bytes` | `int` | no | `1048576` |  |

## `bofbench-packs-internal/file-remove`

Delete one exact operator-supplied file path and report whether it was removed

- Can do: exact file cleanup
- Effects: writes filesystem state
- Needs: privilege=delete access to the exact path; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `path` | `wstring` | yes | `` |  |

## `bofbench-packs-internal/handle-inventory`

Enumerate a bounded set of system handles owned by one explicitly selected process

- Can do: system handle enumeration; process handle filtering
- Effects: reads process metadata
- Needs: privilege=access depends on the selected process; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | `` |  |
| `result_limit` | `int` | no | `64` |  |

## `bofbench-packs-internal/handle-query`

Duplicate one explicitly selected handle and report its object type without using it

- Can do: handle duplication; object type query
- Effects: accesses another process; reads handle metadata
- Needs: privilege=PROCESS_DUP_HANDLE access to the selected process; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `source_pid` | `int` | yes | `` |  |
| `handle_value` | `string` | yes | `` |  |

## `bofbench-packs-internal/logged-on-users`

Enumerate bounded domain and user names associated with local interactive sessions

- Can do: logged-on user discovery; session identity discovery
- Effects: reads session metadata
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `result_limit` | `int` | no | `32` |  |

## `bofbench-packs-internal/module-inventory`

Enumerate bounded module names, paths, bases, and sizes for one process

- Can do: process module discovery
- Effects: reads process metadata
- Needs: privilege=module snapshot access to the selected process; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | `` |  |
| `result_limit` | `int` | no | `32` |  |

## `bofbench-packs-internal/privilege-adjust`

Enable one named privilege on the current BOF loader token and report the result

- Can do: privilege inspection; privilege enablement
- Effects: changes current process token state
- Needs: privilege=the named privilege must be present in the current token; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `privilege_name` | `wstring` | yes | `` |  |

## `bofbench-packs-internal/process-inject`

Write supplied payload bytes into a selected process and start a remote thread

- Can do: remote process access; remote memory write; remote-thread execution
- Effects: accesses another process; writes process memory; starts execution
- Needs: privilege=target process access rights; network=none; platform=windows/x64
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | `` | PID to inject |
| `payload` | `file` | yes | `` | Raw position-independent payload bytes |

## `bofbench-packs-internal/process-memory-read`

Read and print a strictly bounded byte range from one process and hexadecimal address

- Can do: process memory read
- Effects: accesses another process; reads memory
- Needs: privilege=PROCESS_VM_READ and PROCESS_QUERY_LIMITED_INFORMATION on the target; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | `` |  |
| `address` | `string` | yes | `` |  |
| `size` | `int` | no | `64` |  |

## `bofbench-packs-internal/process-minidump`

Open a selected process and write a bounded full-memory minidump to an exact path

- Can do: process memory collection; minidump creation
- Effects: accesses another process; writes a file
- Needs: privilege=target process query and memory-read rights; network=none; platform=windows/x64
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_pid` | `int` | yes | `` |  |
| `output_path` | `wstring` | yes | `` |  |

## `bofbench-packs-internal/remote-service`

Create and start one named service on one operator-supplied host

- Can do: remote service execution; remote service creation
- Effects: reaches a remote system; writes remote system state; starts remote execution
- Needs: privilege=remote service-control administrator rights; network=SMB/RPC to the supplied host; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `remote-service-cleanup`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_host` | `wstring` | yes | `` | exact host name supplied by the operator |
| `service_name` | `wstring` | yes | `` | exact service name |
| `command` | `wstring` | yes | `` | service command line |

## `bofbench-packs-internal/remote-service-cleanup`

Stop and delete one explicitly named service on one operator-supplied host

- Can do: exact remote service cleanup
- Effects: reaches a remote system; writes remote system state
- Needs: privilege=remote service-control administrator rights; network=SMB/RPC to the supplied host; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_host` | `wstring` | yes | `` | exact host name supplied by the operator |
| `service_name` | `wstring` | yes | `` | exact service name |

## `bofbench-packs-internal/run-key`

Create or replace a named current-user Run-key value

- Can do: registry autorun persistence
- Effects: writes state; persists
- Needs: privilege=current-user registry write; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `run-key-cleanup`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `value_name` | `wstring` | yes | `` |  |
| `command` | `wstring` | yes | `` |  |

## `bofbench-packs-internal/run-key-cleanup`

Delete the exact current-user Run-key value supplied by the operator

- Can do: exact registry persistence cleanup
- Effects: writes state
- Needs: privilege=current-user registry write; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `value_name` | `wstring` | yes | `` |  |

## `bofbench-packs-internal/scheduled-task`

Create or replace one explicitly named logon task with an operator-supplied command

- Can do: scheduled task persistence; command execution
- Effects: writes system state; persists; starts execution
- Needs: privilege=rights required for the selected task scope; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `scheduled-task-cleanup`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `task_name` | `wstring` | yes | `` | exact task name |
| `command` | `wstring` | yes | `` | command registered in the task |

## `bofbench-packs-internal/scheduled-task-cleanup`

Delete one explicitly named scheduled task

- Can do: exact scheduled task cleanup
- Effects: writes system state
- Needs: privilege=rights required to delete the selected task; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `task_name` | `wstring` | yes | `` | exact task name |

## `bofbench-packs-internal/service-cleanup`

Stop and delete the exact named service supplied by the operator

- Can do: exact service cleanup
- Effects: writes system state
- Needs: privilege=administrator service-control access; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `service_name` | `wstring` | yes | `` |  |

## `bofbench-packs-internal/service-execution`

Create and start a named Windows service using an operator-supplied binary path

- Can do: service creation; service execution
- Effects: writes system state; starts execution; persists
- Needs: privilege=administrator service-control access; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`
- Cleanup: `service-cleanup`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `service_name` | `wstring` | yes | `` |  |
| `binary_path` | `wstring` | yes | `` |  |

## `bofbench-packs-internal/session-inventory`

Enumerate bounded local Remote Desktop Services session identifiers, names, and states

- Can do: interactive session discovery
- Effects: reads session metadata
- Needs: privilege=user; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `result_limit` | `int` | no | `32` |  |

## `bofbench-packs-internal/share-inventory`

Enumerate a bounded list of shares on one explicitly supplied host

- Can do: network share discovery
- Effects: reads share metadata; reaches a supplied host
- Needs: privilege=share enumeration access; network=SMB/RPC when target is remote; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_host` | `wstring` | yes | `` |  |
| `result_limit` | `int` | no | `64` |  |

## `bofbench-packs-internal/task-inventory`

Enumerate a bounded top-level view of the selected scheduled-task directory

- Can do: scheduled task discovery
- Effects: reads filesystem metadata
- Needs: privilege=read access to the task directory; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `task_root` | `wstring` | yes | `` |  |
| `result_limit` | `int` | no | `64` |  |

## `bofbench-packs-internal/token-impersonation`

Duplicate a token from a selected process, impersonate it, and launch a supplied command under that token

- Can do: token duplication; thread impersonation; alternate-token process creation
- Effects: accesses a security token; changes security context; starts execution
- Needs: privilege=source process access and token duplication rights; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.1.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `source_pid` | `int` | yes | `` | PID whose primary token will be duplicated |
| `command` | `wstring` | yes | `` | Command line to launch |

## `bofbench-packs-internal/token-inventory`

Enumerate bounded process token identity, elevation, and integrity details with an image filter

- Can do: process token enumeration; token identity discovery; integrity discovery
- Effects: reads process metadata; reads security token metadata
- Needs: privilege=token query access to matching processes; network=none; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `process_filter` | `string` | yes | `` |  |
| `result_limit` | `int` | no | `25` |  |

## `bofbench-packs-internal/wmi-process-create`

Use Win32_Process.Create for one supplied host and command under the current security context

- Can do: WMI remote execution; process creation
- Effects: reaches a supplied host; starts execution
- Needs: privilege=WMI process-create rights on the supplied host; network=DCOM/RPC when target is remote; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target_host` | `wstring` | yes | `` |  |
| `command` | `wstring` | yes | `` |  |

## `bofbench-packs-internal/wmi-query`

Run one explicit WQL query in a supplied namespace and print one property from bounded results

- Can do: WMI query; host and process discovery
- Effects: reads system management data
- Needs: privilege=WMI namespace access; network=required only for a remote namespace; platform=windows/x64,x86
- Works with: native, lab, sliver, cobaltstrike
- Version: `1.0.0`

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `namespace` | `wstring` | yes | `` |  |
| `query` | `wstring` | yes | `` |  |
| `property` | `wstring` | yes | `` |  |
| `result_limit` | `int` | no | `20` |  |

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

| Argument | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `process_filter` | `string` | no | `` | case-insensitive process image substring; empty matches all |
| `result_limit` | `int` | no | `25` | maximum matching process rows (1-256) |

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

