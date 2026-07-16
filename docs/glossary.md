# Glossary

| Term | BOFBench meaning |
| --- | --- |
| Analyzer signature | Declarative function-local API/string pattern that names an operator capability |
| Arsenal | Indexed collection of external BOF source, metadata, and objects |
| Behavior chain | Related operations evidenced in one function, such as open → allocate → write → execute |
| BOF | Beacon Object File: a COFF object loaded into an existing runtime rather than a standalone executable |
| Catalog | Named source of capability packs |
| DAG operation | A version-6 operation whose steps run when their declared dependencies are complete |
| Background step | A bounded version-7 DAG step that emits a readiness result, remains active, and later must satisfy a terminal result contract |
| Readiness dependency | `depends_on_ready`; permits a descendant to start after an exact ready contract without waiting for the background producer to finish |
| Cleanup companion | Pack that reverses or removes a named action when the operator requests it |
| Effects | Data read, state write, execution, persistence, authentication-material access, or remote reach |
| Exact-hash correlation | Attaching runtime observation only when receipt and analysis object hashes match |
| Export | Verified raw, Sliver, or Cobalt Strike operator package |
| Guard mode | Optional hash or identity verification requested by the operator |
| Lab profile | Global named connection/build/runtime configuration for one Windows machine |
| Loader support | Whether imports, relocations, architecture, and entrypoint can be handled by the selected loader |
| Lock | `bofbench.lock.json` record of resolved pack versions, hashes, and contracts |
| Observed | Runtime-confirmed output linked to the analyzed object hash |
| Pack | Reusable capability contract containing source, arguments, analysis, output, runtime, proof, and optional cleanup |
| Project | Generated BOF source composed from one or more packs |
| Proof | Manifest-declared runtime case with expected output and optional independent state verification |
| Receipt | `bofbench.runtime-receipt` JSON result normalized across runtime adapters |
| Ready wave | Set of dependency-satisfied DAG steps fully prepared before concurrent execution |
| Runtime refresh | Adapter request that updates a persisted C2 receipt from its recorded session and task |
| Source and version | Repository, revision, object path, and object hash when known |
| Topology | Named mapping from execution, target, and domain-controller roles to lab profiles |
| Typed argument | Runtime value packed as string, wide string, integer, short, bytes, or file |

The default UI uses direct operator language. Framework identifiers may exist as machine-readable metadata but do not replace the capability description.
