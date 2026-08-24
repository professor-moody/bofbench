#!/usr/bin/env python3
"""Verify the digest-bound BOFBench release qualification boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


VALID_STATUSES = {"passed", "withheld", "unavailable"}


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"expected a JSON object: {path}")
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def plain_digest(value: str) -> str:
    return value.removeprefix("sha256:")


def expect(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"{label}: expected {expected!r}, got {actual!r}")


def safe_path(root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        fail(f"unsafe repository-relative path: {relative!r}")
    resolved = (root / Path(*candidate.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"path leaves repository root: {relative!r}")
    return resolved


def git(repo: Path, *args: str, binary: bool = False) -> str | bytes:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), *args],
            text=not binary,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.output.decode(errors="replace") if isinstance(exc.output, bytes) else exc.output
        fail(f"git {' '.join(args)} failed in {repo}: {output.strip()}")


def verify_repo_ref(repo: Path, commit: str, relative: str, digest: str) -> Path:
    path = safe_path(repo, relative)
    expect(sha256_file(path), plain_digest(digest), f"working-tree digest for {relative}")
    historical = git(repo, "show", f"{commit}:{relative}", binary=True)
    assert isinstance(historical, bytes)
    expect(sha256_bytes(historical), plain_digest(digest), f"commit-bound digest for {relative}")
    return path


def require_clean(repo: Path) -> None:
    status = git(repo, "status", "--porcelain")
    assert isinstance(status, str)
    if status.strip():
        fail(f"repository is not clean: {repo}")


def check_statuses(document: dict[str, Any]) -> None:
    values: list[tuple[str, str]] = []
    for section in ("static_cells", "live_cells", "withheld_cells"):
        for item in document[section]:
            values.append((f"{section}.{item.get('id', '<missing>')}", item.get("status")))
    values.extend(
        [
            ("release", document["release"].get("status")),
            ("catalog", document["catalog"].get("status")),
            ("edr_consumer", document["edr_consumer"].get("status")),
            ("publication", document["publication"].get("status")),
        ]
    )
    for label, status in values:
        if status not in VALID_STATUSES:
            fail(f"{label}.status must be one of {sorted(VALID_STATUSES)}, got {status!r}")


def static_cells(gate: dict[str, Any]) -> list[dict[str, Any]]:
    cells: list[dict[str, Any]] = []
    for scope, key in (("packs", "pack_test"), ("operations", "operation_test")):
        for source in gate["static_matrix"][key]["summary"]["build_cells"]:
            status = {"pass": "passed", "unavailable": "unavailable"}.get(source["status"])
            if status is None:
                fail(f"unexpected catalog static status: {source['status']!r}")
            cells.append(
                {
                    "id": f"{scope}-{source['compiler']}-{source['architecture']}",
                    "scope": scope,
                    "compiler": source["compiler"],
                    "architecture": source["architecture"],
                    "status": status,
                    "cell_count": source["count"],
                }
            )
    return sorted(cells, key=lambda item: item["id"])


def live_cell(kind: str, source: dict[str, Any]) -> dict[str, Any]:
    subject_key = "operation" if kind == "operation" else "pack"
    suffix = f"-{source['session_context']}" if source.get("session_context") else ""
    return {
        "id": (
            f"{kind}-{source[subject_key]}-{source['proof_case']}-"
            f"{source['runtime']}-{source['architecture']}{suffix}"
        ),
        "kind": kind,
        "subject": source[subject_key],
        "proof_case": source["proof_case"],
        "runtime": source["runtime"],
        "architecture": source["architecture"],
        **({"session_context": source["session_context"]} if source.get("session_context") else {}),
        "status": "passed" if source["status"] == "pass" else source["status"],
        "cleanup_status": "passed" if source["cleanup"] == "pass" else source["cleanup"],
        "receipt_path": source["receipt"]["path"],
        "receipt_sha256": source["receipt"]["sha256"],
    }


def verify_release(document: dict[str, Any], root: Path, artifact_root: Path | None) -> None:
    release = document["release"]
    reference = release["receipt"]
    receipt_path = verify_repo_ref(root, reference["commit"], reference["path"], reference["sha256"])
    receipt = load_json(receipt_path)
    expect(receipt.get("schema"), "bofbench.local-release-receipt", "release receipt schema")
    expect(receipt.get("schema_version"), 1, "release receipt schema version")
    expect(receipt.get("status"), "pass", "release receipt status")
    expect(receipt.get("version"), release["version"], "release version")
    expect(receipt["source"]["commit"], release["source_commit"], "release source commit")
    expect(receipt["source"]["working_tree_clean"], True, "release source cleanliness")
    expect(receipt["checksums"]["sha256"], release["checksums_sha256"], "checksum-file digest")
    expect(receipt["checksums"]["verified"], True, "checksum verification")
    expected_artifacts = [
        {"path": item["path"], "sha256": item["sha256"]} for item in receipt["artifacts"]
    ]
    expect(release["artifacts"], expected_artifacts, "release artifact boundary")
    expect(receipt["distribution"], {"tag_created": False, "published": False, "pushed": False}, "distribution state")

    if artifact_root is not None:
        for item in release["artifacts"]:
            path = safe_path(artifact_root, item["path"])
            expect(sha256_file(path), item["sha256"], f"release artifact {item['path']}")
        sums_path = safe_path(artifact_root, receipt["checksums"]["path"])
        expect(sha256_file(sums_path), release["checksums_sha256"], "release SHA256SUMS")


def verify_catalog(document: dict[str, Any], root: Path, private_root: Path) -> None:
    catalog = document["catalog"]
    gate_path = verify_repo_ref(
        private_root,
        catalog["receipt_commit"],
        catalog["receipt_path"],
        catalog["receipt_sha256"],
    )
    gate = load_json(gate_path)
    expect(gate.get("schema"), "bofbench.internal-catalog-release-gate", "catalog gate schema")
    expect(gate.get("schema_version"), 1, "catalog gate schema version")
    expect(gate.get("release_id"), catalog["release_id"], "catalog release ID")
    expect(gate.get("decision"), "qualified_for_declared_floor", "catalog decision")
    expect(gate["compatibility"]["bofbench"]["version"], document["release"]["version"], "catalog BOFBench version")
    expect(
        gate["compatibility"]["bofbench"]["canonical_tested_commit"],
        catalog["canonical_bofbench_commit"],
        "catalog canonical BOFBench commit",
    )
    expect(gate["compatibility"]["catalog"]["pack_count"], catalog["pack_count"], "catalog pack count")
    expect(gate["compatibility"]["catalog"]["operation_count"], catalog["operation_count"], "catalog operation count")
    expect(
        gate["compatibility"]["bofbench"]["minimum_compatible_commit"],
        catalog["minimum_compatible_bofbench_commit"],
        "catalog minimum compatible BOFBench commit",
    )
    expect(gate["static_matrix"]["canonical_matches_compatibility_floor"], True, "static compatibility match")
    expect(
        sorted(document["static_cells"], key=lambda item: item["id"]),
        static_cells(gate),
        "declared static cells",
    )

    selected = [live_cell("operation", item) for item in gate["live_matrix"]["cells"]]
    selected.extend(live_cell("pack", item) for item in gate["pack_live_matrix"]["cells"])
    expect(
        sorted(document["live_cells"], key=lambda item: item["id"]),
        sorted(selected, key=lambda item: item["id"]),
        "selected live cells",
    )
    expect(gate["live_matrix"]["qualified_cells"], 8, "operation live-cell count")
    expect(gate["live_matrix"]["cleanup_cells"], 8, "operation cleanup count")
    expect(gate["pack_live_matrix"]["qualified_cells"], 1, "pack live-cell count")
    expect(gate["pack_live_matrix"]["cleanup_cells"], 1, "pack cleanup count")
    for cell in document["live_cells"]:
        verify_repo_ref(private_root, catalog["receipt_commit"], cell["receipt_path"], cell["receipt_sha256"])

    ancestry_pairs = (
        (
            catalog["minimum_compatible_bofbench_commit"],
            document["release"]["source_commit"],
            "release source commit is older than the catalog compatibility floor",
        ),
        (
            document["release"]["source_commit"],
            catalog["canonical_bofbench_commit"],
            "release source commit is not an ancestor of the catalog-tested BOFBench commit",
        ),
    )
    for older, newer, message in ancestry_pairs:
        ancestry = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", older, newer],
            check=False,
        )
        if ancestry.returncode != 0:
            fail(message)


def verify_edr(document: dict[str, Any], root: Path, edrlab_root: Path) -> None:
    boundary = document["edr_consumer"]
    consumer_ref = boundary["consumer_receipt"]
    consumer_path = verify_repo_ref(
        root, consumer_ref["commit"], consumer_ref["path"], consumer_ref["sha256"]
    )
    consumer = load_json(consumer_path)
    expect(consumer.get("schema"), "bofbench.edrlab-consumer-result/v1", "consumer receipt schema")
    expect(consumer.get("status"), "qualified", "consumer receipt status")

    result_ref = boundary["result_receipt"]
    expect(consumer["consumer"]["receipt_commit"], result_ref["commit"], "EDR result commit")
    expect(consumer["consumer"]["receipt_path"], result_ref["path"], "EDR result path")
    expect(
        plain_digest(consumer["consumer"]["receipt_sha256"]),
        result_ref["sha256"],
        "EDR result digest",
    )
    result_path = verify_repo_ref(
        edrlab_root, result_ref["commit"], result_ref["path"], result_ref["sha256"]
    )
    result = load_json(result_path)
    expect(result.get("schema"), "edrlab.bofbench-artifact-qualified-result/v1", "EDR result schema")
    expect(result.get("status"), "qualified", "EDR result status")
    expect(result["stopping_rule"]["accepted_runs"], 3, "EDR accepted-run count")
    expect(result["stopping_rule"]["disagreements"], 0, "EDR disagreement count")

    expected_products = []
    cleanup = 0
    destroyed = 0
    for product in ("defender", "elastic"):
        outcomes = [item[product] for item in result["repetitions"]]
        classifications = {item["outcome"] for item in outcomes}
        if len(classifications) != 1:
            fail(f"EDR {product} outcomes disagree: {sorted(classifications)}")
        expected_products.append(
            {
                "product": product,
                "classification": next(iter(classifications)),
                "repetitions": len(outcomes),
                "status": "passed",
            }
        )
        cleanup += sum(item["cleanup_verified"] is True for item in outcomes)
        destroyed += sum(item["clone_destroyed"] is True for item in outcomes)
    expect(boundary["products"], expected_products, "EDR product classifications")
    expect(boundary["cleanup_status"], "passed", "EDR cleanup status")
    expect(boundary["cleanup_repetitions"], cleanup, "EDR cleanup repetitions")
    expect(boundary["clone_destruction_status"], "passed", "EDR clone-destruction status")
    expect(boundary["clone_destruction_repetitions"], destroyed, "EDR clone-destruction repetitions")
    expect(consumer["scoring"]["visibility_score"], "withheld", "visibility scoring status")
    expect(consumer["scoring"]["stealth_score"], "withheld", "stealth scoring status")


def verify_withheld(document: dict[str, Any]) -> None:
    expected = {
        "unselected-pack-live-and-cleanup",
        "unselected-operation-live-and-cleanup",
        "runtime-comparison-contracts",
        "cobalt-strike-live-execution",
        "edr-visibility-score",
        "edr-stealth-score",
    }
    actual = {item["id"] for item in document["withheld_cells"]}
    expect(actual, expected, "withheld coverage IDs")
    expect(document["publication"]["status"], "withheld", "publication status")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    script_root = Path(__file__).resolve().parent.parent
    suite_root = script_root.parent
    parser.add_argument(
        "--manifest",
        type=Path,
        default=script_root / "qualification/release-manifest-0.1.0.json",
    )
    parser.add_argument("--root", type=Path, default=script_root)
    parser.add_argument("--private-root", type=Path, default=suite_root / "bofbench-packs-internal")
    parser.add_argument("--edrlab-root", type=Path, default=suite_root / "edrlab")
    parser.add_argument(
        "--artifact-root",
        type=Path,
        help="optionally verify the release archives and SHA256SUMS under this BOFBench checkout",
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="also require clean BOFBench, private catalog, and EDR Lab working trees",
    )
    args = parser.parse_args()

    try:
        root = args.root.resolve()
        private_root = args.private_root.resolve()
        edrlab_root = args.edrlab_root.resolve()
        manifest_path = args.manifest.resolve()
        document = load_json(manifest_path)
        expect(
            set(document),
            {
                "schema",
                "manifest_id",
                "issued_at",
                "decision",
                "release",
                "catalog",
                "static_cells",
                "live_cells",
                "edr_consumer",
                "withheld_cells",
                "publication",
                "claim_boundary",
            },
            "manifest top-level fields",
        )
        expect(document["schema"], "bofbench.release-qualification-manifest/v1", "manifest schema")
        expect(document["decision"], "qualified_with_unavailable", "manifest decision")
        check_statuses(document)
        ids = [item["id"] for section in ("static_cells", "live_cells", "withheld_cells") for item in document[section]]
        if len(ids) != len(set(ids)):
            fail("coverage cell IDs are not unique")
        verify_release(document, root, args.artifact_root.resolve() if args.artifact_root else None)
        verify_catalog(document, root, private_root)
        verify_edr(document, root, edrlab_root)
        verify_withheld(document)
        if args.require_clean:
            for repo in (root, private_root, edrlab_root):
                require_clean(repo)
    except VerificationError as exc:
        print(f"release manifest verification failed: {exc}", file=sys.stderr)
        return 1

    digest = sha256_file(manifest_path)
    print(
        "release manifest verified: "
        f"{document['manifest_id']} sha256:{digest} "
        f"({len(document['live_cells'])} live cells, "
        f"{len(document['withheld_cells'])} withheld cells)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
