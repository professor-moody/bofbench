#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib


def digest(path: str) -> str:
    return "sha256:" + hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--visibility", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    bundle = json.loads(pathlib.Path(args.bundle).read_text())
    matrix = json.loads(pathlib.Path(args.matrix).read_text())
    visibility = json.loads(pathlib.Path(args.visibility).read_text())
    failures = []
    if bundle.get("schema_version") != "windows.artifact-bundle/v1" or bundle.get("provenance", {}).get("producer") != "bofbench":
        failures.append("BOFBench bundle identity is invalid")
    if matrix.get("dirty") or matrix.get("outcome") != "completed":
        failures.append("EDR matrix did not complete cleanly")
    for run in matrix.get("runs", []):
        if run.get("outcome") != "functional" or not run.get("effect_succeeded"):
            failures.append(f"nonfunctional BOF run: {run.get('product')}")
        if not run.get("cleanup_complete") or not run.get("workspace_clean") or not run.get("lease", {}).get("destroyed"):
            failures.append(f"dirty BOF run: {run.get('product')}")
        required = set(run.get("product_evidence", {}).get("required_sensors", []))
        completed = set(run.get("product_evidence", {}).get("completed_sensors", []))
        if required - completed or not run.get("product_evidence", {}).get("controller_evidence_sha256"):
            failures.append(f"incomplete BOF sensor evidence: {run.get('product')}")
    for run in visibility.get("runs", []):
        if not run.get("scored"):
            failures.append(f"unscored BOF run: {run.get('product')}")
    receipt = {
        "schema_version": "bofbench.operator-lab-live/v1",
        "status": "passed" if not failures else "failed",
        "bundle_sha256": digest(args.bundle),
        "matrix_sha256": digest(args.matrix),
        "visibility_sha256": digest(args.visibility),
        "failures": sorted(set(failures)),
    }
    target = pathlib.Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(receipt, handle, sort_keys=True, indent=2)
        handle.write("\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(target)}, sort_keys=True))
    return 0 if not failures else 3


if __name__ == "__main__":
    raise SystemExit(main())
