# Sanitized Documentation Evidence

These fixtures preserve schemas, status semantics, output tags, and field names used by handbook examples. Dynamic identifiers, host details, object hashes, paths, timestamps, and secrets are replaced or omitted.

They support documentation validation and media generation; they are not substitutes for current live runtime receipts.

`command-compatibility-v1.json` is different: it is the versioned, deterministic policy contract for retained legacy commands. `bofbench compatibility` renders the same source policy, and the documentation check rejects either JSON or Markdown drift.
