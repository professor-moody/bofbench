#!/usr/bin/env python3
"""Evaluate a frozen third-party BOF corpus without changing its labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ACCEPTED_SUPPORT = {"compatible", "compatible_runtime_lookup"}


def fail(message: str) -> None:
    raise SystemExit(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_text(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        fail(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def run_json(command: list[str], cwd: Path) -> dict[str, Any]:
    output = run_text(command, cwd)
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        fail(f"command returned malformed JSON: {' '.join(command)}: {error}")
    if not isinstance(value, dict):
        fail(f"command did not return a JSON object: {' '.join(command)}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def exact_labels(values: Any, label: str) -> list[str]:
    if not isinstance(values, list) or any(
        not isinstance(value, str) for value in values
    ):
        fail(f"{label} must be a string list")
    if values != sorted(set(values)):
        fail(f"{label} must be sorted and unique")
    return values


def metric(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": (
            {"state": "measured", "value": tp / precision_denominator}
            if precision_denominator
            else {"state": "withheld", "reason": "no positive analyzer labels"}
        ),
        "recall": (
            {"state": "measured", "value": tp / recall_denominator}
            if recall_denominator
            else {"state": "withheld", "reason": "no positive reviewed labels"}
        ),
    }


def add_confusion(
    counter: Counter[str], expected: list[str], actual: list[str]
) -> None:
    expected_set = set(expected)
    actual_set = set(actual)
    counter["tp"] += len(expected_set & actual_set)
    counter["fp"] += len(actual_set - expected_set)
    counter["fn"] += len(expected_set - actual_set)


def add_binary_confusion(
    counter: Counter[str], expected_positive: bool, actual_positive: bool
) -> None:
    if expected_positive and actual_positive:
        counter["tp"] += 1
    elif actual_positive:
        counter["fp"] += 1
    elif expected_positive:
        counter["fn"] += 1


def require_repo_path(root: Path, value: str, label: str) -> Path:
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        fail(f"{label} escapes the repository: {value}")
    return candidate


def repo_relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def load_layer_sources(
    root: Path,
    provenance: dict[str, Any],
    schema_version: int,
    layer_id: str,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    lock_value = provenance.get("object_lock")
    lock_digest = provenance.get("object_lock_sha256")
    if not isinstance(lock_value, str) or not lock_value:
        fail(f"corpus layer {layer_id} has no object lock")
    if not isinstance(lock_digest, str) or len(lock_digest) != 64:
        fail(f"corpus layer {layer_id} has no object-lock digest")
    lock_path = require_repo_path(root, lock_value, f"{layer_id} object lock")
    if sha256(lock_path) != lock_digest:
        fail(f"corpus layer {layer_id} object-lock digest does not match")
    lock = load_json(lock_path)
    if lock.get("schema") != "bofbench.corpus-lock" or lock.get("schema_version") != 1:
        fail(f"corpus layer {layer_id} has an unsupported object lock")
    repositories = lock.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        fail(f"corpus layer {layer_id} object lock has no repositories")

    if schema_version == 1:
        declarations: Any = [
            {
                field: provenance.get(field)
                for field in ("name", "repository", "commit", "root")
            }
        ]
    else:
        declarations = provenance.get("sources")
    if not isinstance(declarations, list) or not declarations:
        fail(f"corpus layer {layer_id} has no source declarations")
    if len(declarations) != len(repositories):
        fail(f"corpus layer {layer_id} source count does not match its object lock")

    repositories_by_name: dict[str, dict[str, Any]] = {}
    for repository in repositories:
        if not isinstance(repository, dict):
            fail(f"corpus layer {layer_id} object-lock repository is malformed")
        name = repository.get("name")
        if not isinstance(name, str) or not name or name in repositories_by_name:
            fail(f"corpus layer {layer_id} object lock has a duplicate source")
        repositories_by_name[name] = repository

    sources: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for declaration in declarations:
        if not isinstance(declaration, dict):
            fail(f"corpus layer {layer_id} source declaration is malformed")
        name = declaration.get("name")
        if not isinstance(name, str) or not name or name in seen_names:
            fail(f"corpus layer {layer_id} has a duplicate source declaration")
        seen_names.add(name)
        locked_repository = repositories_by_name.get(name)
        if locked_repository is None:
            fail(
                f"corpus layer {layer_id} source {name} is absent from its object lock"
            )
        for field in ("name", "repository", "commit", "root"):
            if declaration.get(field) != locked_repository.get(field):
                fail(
                    f"corpus layer {layer_id} source {name} field {field} "
                    "does not match its object lock"
                )
        object_root = require_repo_path(
            root, str(declaration.get("root", "")), f"{layer_id} source {name} root"
        )
        if not object_root.is_dir():
            fail(f"corpus layer {layer_id} source {name} checkout is unavailable")
        checkout_commit = run_text(["git", "rev-parse", "HEAD"], object_root).strip()
        if checkout_commit != declaration["commit"]:
            fail(
                f"corpus layer {layer_id} source {name} checkout is at "
                f"{checkout_commit}, want {declaration['commit']}"
            )
        locked_objects: dict[str, str] = {}
        objects = locked_repository.get("objects")
        if not isinstance(objects, list) or not objects:
            fail(f"corpus layer {layer_id} source {name} has no locked objects")
        for item in objects:
            if not isinstance(item, dict):
                fail(f"corpus layer {layer_id} source {name} has a malformed object")
            path = item.get("path")
            digest = item.get("sha256")
            if (
                not isinstance(path, str)
                or not path
                or not isinstance(digest, str)
                or len(digest) != 64
                or path in locked_objects
            ):
                fail(f"corpus layer {layer_id} source {name} has an invalid object")
            locked_objects[path] = digest
        review_sources: list[dict[str, str]] = []
        for item in locked_repository.get("review_sources", []):
            if not isinstance(item, dict):
                fail(
                    f"corpus layer {layer_id} source {name} has malformed review source"
                )
            path = item.get("path")
            digest = item.get("sha256")
            if (
                not isinstance(path, str)
                or not path
                or not isinstance(digest, str)
                or len(digest) != 64
            ):
                fail(f"corpus layer {layer_id} source {name} has invalid review source")
            source_path = require_repo_path(
                object_root, path, f"{layer_id} source {name} review source"
            )
            if sha256(source_path) != digest:
                fail(
                    f"corpus layer {layer_id} source {name} review-source digest "
                    f"does not match: {path}"
                )
            review_sources.append({"path": path, "sha256": digest})
        sources.append(
            {
                "name": name,
                "repository": declaration["repository"],
                "commit": declaration["commit"],
                "root": declaration["root"],
                "object_root": object_root,
                "objects": locked_objects,
                "review_sources": review_sources,
                "object_lock": lock_value,
                "object_lock_sha256": lock_digest,
            }
        )
    return sources, {"path": lock_value, "sha256": lock_digest}


def resolve_corpus(
    root: Path,
    corpus_path: Path,
    expected_digest: str | None = None,
    seen: set[Path] | None = None,
) -> dict[str, Any]:
    corpus_path = corpus_path.resolve()
    seen = set() if seen is None else seen
    if corpus_path in seen:
        fail(f"corpus inheritance cycle at {corpus_path}")
    seen.add(corpus_path)
    digest = sha256(corpus_path)
    if expected_digest is not None and digest != expected_digest:
        fail(
            f"inherited corpus digest does not match: {repo_relative(root, corpus_path)}"
        )
    corpus = load_json(corpus_path)
    schema_version = corpus.get("schema_version")
    if (
        corpus.get("schema") != "bofbench.analyzer-evaluation-corpus"
        or schema_version not in (1, 2)
        or corpus.get("state") != "labels_frozen"
    ):
        fail("corpus is not a frozen bofbench.analyzer-evaluation-corpus/v1 or /v2")
    corpus_id = corpus.get("corpus_id")
    if not isinstance(corpus_id, str) or not corpus_id:
        fail("corpus has no identity")

    sources: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    layers: list[dict[str, Any]] = []
    if schema_version == 2:
        extends = corpus.get("extends")
        if not isinstance(extends, dict):
            fail(f"corpus layer {corpus_id} has no inherited corpus")
        base_value = extends.get("corpus")
        base_digest = extends.get("corpus_sha256")
        if not isinstance(base_value, str) or not isinstance(base_digest, str):
            fail(f"corpus layer {corpus_id} has malformed inheritance")
        base_path = require_repo_path(root, base_value, f"{corpus_id} inherited corpus")
        base = resolve_corpus(root, base_path, base_digest, seen)
        if (
            extends.get("object_lock") != base["layers"][-1]["object_lock"]
            or extends.get("object_lock_sha256")
            != base["layers"][-1]["object_lock_sha256"]
        ):
            fail(f"corpus layer {corpus_id} does not bind its base object lock")
        sources.extend(base["sources"])
        cases.extend(base["cases"])
        layers.extend(base["layers"])

    provenance = corpus.get("provenance")
    if not isinstance(provenance, dict):
        fail(f"corpus layer {corpus_id} has no provenance")
    layer_sources, object_lock = load_layer_sources(
        root, provenance, int(schema_version), corpus_id
    )
    existing_sources = {source["name"] for source in sources}
    for source in layer_sources:
        if source["name"] in existing_sources:
            fail(f"corpus layer {corpus_id} repeats source {source['name']}")
        existing_sources.add(source["name"])
        sources.append(source)

    raw_cases = corpus.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        fail(f"corpus layer {corpus_id} has no cases")
    default_source = layer_sources[0]["name"] if schema_version == 1 else None
    for case in raw_cases:
        if not isinstance(case, dict):
            fail(f"corpus layer {corpus_id} has a malformed case")
        resolved_case = dict(case)
        source_name = case.get("source", default_source)
        if source_name not in existing_sources:
            fail(f"corpus case {case.get('id', '')} names an unknown source")
        resolved_case["source"] = source_name
        cases.append(resolved_case)

    case_ids = [case.get("id") for case in cases]
    if any(not isinstance(case_id, str) or not case_id for case_id in case_ids):
        fail("corpus contains a case without an identity")
    if len(case_ids) != len(set(case_ids)):
        fail("corpus contains duplicate case identities")
    layers.append(
        {
            "id": corpus_id,
            "path": repo_relative(root, corpus_path),
            "sha256": digest,
            "object_lock": object_lock["path"],
            "object_lock_sha256": object_lock["sha256"],
            "limitations": corpus.get("limitations"),
        }
    )
    return {
        "schema_version": schema_version,
        "id": corpus_id,
        "path": repo_relative(root, corpus_path),
        "sha256": digest,
        "limitations": corpus.get("limitations"),
        "sources": sources,
        "cases": cases,
        "layers": layers,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", default="work/bin/bofbench")
    parser.add_argument("--corpus", default="testdata/analyzer-corpus-v1.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    corpus_path = require_repo_path(root, args.corpus, "corpus path")
    output_path = require_repo_path(root, args.output, "output path")
    binary = require_repo_path(root, args.bin, "binary path")
    resolved = resolve_corpus(root, corpus_path)

    status = run_text(["git", "status", "--porcelain"], root)
    if status.strip():
        fail("evaluation requires a clean BOFBench checkout")
    source_commit = run_text(["git", "rev-parse", "HEAD"], root).strip()
    for layer in resolved["layers"]:
        layer["labels_frozen_commit"] = run_text(
            ["git", "log", "-1", "--format=%H", "--", layer["path"]], root
        ).strip()

    version = run_json([str(binary), "version", "--format", "json"], root)
    tool = version.get("tool", {})
    if not isinstance(tool, dict) or tool.get("commit") != source_commit:
        fail(
            f"binary commit {tool.get('commit') if isinstance(tool, dict) else ''} "
            f"does not match checkout {source_commit}"
        )

    signature_sets: dict[str, str] = {}
    for source in resolved["sources"]:
        inventory = run_json(
            [
                str(binary),
                "arsenal",
                "inventory",
                str(source["object_root"]),
                "--format",
                "json",
            ],
            root,
        )
        signature_set = inventory.get("analyzer_signature_set")
        if not isinstance(signature_set, str) or len(signature_set) != 64:
            fail(
                f"arsenal inventory for {source['name']} did not return an "
                "analyzer signature-set digest"
            )
        signature_sets[source["name"]] = signature_set
    if len(set(signature_sets.values())) != 1:
        fail("source inventories used different analyzer signature sets")
    signature_set = next(iter(signature_sets.values()))

    sources_by_name = {source["name"]: source for source in resolved["sources"]}
    support_counts: Counter[str] = Counter()
    blocked_objects: Counter[str] = Counter()
    capabilities: Counter[str] = Counter()
    behavior_chains: Counter[str] = Counter()
    interprocedural: Counter[str] = Counter()
    pair_agreement = 0
    results: list[dict[str, Any]] = []

    for case in resolved["cases"]:
        case_id = str(case.get("id", ""))
        source_name = str(case.get("source", ""))
        source = sources_by_name[source_name]
        objects = case.get("objects", {})
        expected_support = case.get("expected_support", {})
        labels = case.get("labels", {})
        if not all(
            isinstance(value, dict) for value in (objects, expected_support, labels)
        ):
            fail(f"case {case_id} is malformed")
        expected_capabilities = exact_labels(
            labels.get("capabilities"), f"{case_id} capabilities"
        )
        expected_chains = exact_labels(
            labels.get("behavior_chains"), f"{case_id} behavior chains"
        )
        expected_interprocedural = exact_labels(
            labels.get("interprocedural_behavior_chains"),
            f"{case_id} interprocedural chains",
        )
        architectures: list[dict[str, Any]] = []
        actual_by_arch: dict[str, tuple[list[str], list[str], list[str]]] = {}
        for arch in ("x64", "x86"):
            relative = objects.get(arch)
            if not isinstance(relative, str) or relative not in source["objects"]:
                fail(
                    f"case {case_id} {arch} object is not in the frozen object lock "
                    f"for {source_name}"
                )
            object_path = require_repo_path(
                source["object_root"], relative, f"case {case_id} {arch} object"
            )
            object_digest = sha256(object_path)
            if object_digest != source["objects"][relative]:
                fail(f"case {case_id} {arch} object digest mismatch")
            payload = run_json(
                [str(binary), "analyze", str(object_path), "--format", "json"], root
            )
            analysis = payload.get("analysis", {})
            if (
                not isinstance(analysis, dict)
                or analysis.get("sha256") != object_digest
            ):
                fail(f"case {case_id} {arch} analysis did not bind the object digest")
            actual_support = str(
                (analysis.get("loader_compatibility") or {}).get("status", "")
            )
            actual_capabilities = sorted(
                {
                    str(item.get("id"))
                    for item in analysis.get("capabilities", [])
                    if item.get("id")
                }
            )
            chains = analysis.get("behavior_chains", [])
            actual_chains = sorted(
                {str(item.get("id")) for item in chains if item.get("id")}
            )
            actual_interprocedural = sorted(
                {
                    str(item.get("id"))
                    for item in chains
                    if item.get("id") and item.get("interprocedural") is True
                }
            )
            expected = str(expected_support.get(arch, ""))
            if not expected:
                fail(f"case {case_id} has no expected {arch} support class")
            support_counts["total"] += 1
            support_counts["correct"] += int(actual_support == expected)
            support_counts["expected_" + expected] += 1
            add_binary_confusion(
                blocked_objects,
                expected not in ACCEPTED_SUPPORT,
                actual_support not in ACCEPTED_SUPPORT,
            )
            add_confusion(capabilities, expected_capabilities, actual_capabilities)
            add_confusion(behavior_chains, expected_chains, actual_chains)
            add_confusion(
                interprocedural, expected_interprocedural, actual_interprocedural
            )
            differences = {
                "support": actual_support != expected,
                "capabilities": actual_capabilities != expected_capabilities,
                "behavior_chains": actual_chains != expected_chains,
                "interprocedural_behavior_chains": actual_interprocedural
                != expected_interprocedural,
            }
            architectures.append(
                {
                    "architecture": arch,
                    "path": relative,
                    "sha256": object_digest,
                    "expected": {
                        "support": expected,
                        "capabilities": expected_capabilities,
                        "behavior_chains": expected_chains,
                        "interprocedural_behavior_chains": expected_interprocedural,
                    },
                    "actual": {
                        "support": actual_support,
                        "capabilities": actual_capabilities,
                        "behavior_chains": actual_chains,
                        "interprocedural_behavior_chains": actual_interprocedural,
                    },
                    "differences": differences,
                    "status": "pass" if not any(differences.values()) else "mismatch",
                }
            )
            actual_by_arch[arch] = (
                actual_capabilities,
                actual_chains,
                actual_interprocedural,
            )
        agrees = actual_by_arch["x64"] == actual_by_arch["x86"]
        pair_agreement += int(agrees)
        results.append(
            {
                "id": case_id,
                "source": source_name,
                "architecture_label_agreement": agrees,
                "status": (
                    "pass"
                    if agrees
                    and all(item["status"] == "pass" for item in architectures)
                    else "mismatch"
                ),
                "architectures": architectures,
            }
        )

    mismatches = sum(item["status"] != "pass" for item in results)
    mismatched_objects = sum(
        architecture["status"] != "pass"
        for result in results
        for architecture in result["architectures"]
    )
    public_sources = [
        {
            key: source[key]
            for key in (
                "name",
                "repository",
                "commit",
                "root",
                "object_lock",
                "object_lock_sha256",
                "review_sources",
            )
        }
        for source in resolved["sources"]
    ]
    corpus_report: dict[str, Any] = {
        "id": resolved["id"],
        "path": resolved["path"],
        "sha256": resolved["sha256"],
        "labels_frozen_commit": resolved["layers"][-1]["labels_frozen_commit"],
    }
    if resolved["schema_version"] == 1:
        corpus_report.update(
            {
                "object_lock_sha256": resolved["layers"][-1]["object_lock_sha256"],
                "upstream_commit": public_sources[0]["commit"],
            }
        )
    else:
        corpus_report.update(
            {
                "layers": resolved["layers"],
                "sources": public_sources,
            }
        )

    report = {
        "schema": "bofbench.analyzer-corpus-evaluation",
        "schema_version": resolved["schema_version"],
        "status": "pass" if mismatches == 0 else "mismatch",
        "evaluated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "corpus": corpus_report,
        "analyzer": {
            "source_commit": source_commit,
            "binary_sha256": sha256(binary),
            "tool": tool,
            "host": version.get("host"),
            "signature_set_sha256": signature_set,
            "source_inventory_signature_sets": signature_sets,
        },
        "summary": {
            "cases": len(results),
            "objects": sum(len(item["architectures"]) for item in results),
            "mismatched_cases": mismatches,
            "mismatched_objects": mismatched_objects,
            "loader_support": {
                "correct": support_counts["correct"],
                "total": support_counts["total"],
                "accuracy": support_counts["correct"] / support_counts["total"],
                "expected_classes": {
                    key.removeprefix("expected_"): value
                    for key, value in sorted(support_counts.items())
                    if key.startswith("expected_")
                },
                "blocked_objects": metric(
                    blocked_objects["tp"],
                    blocked_objects["fp"],
                    blocked_objects["fn"],
                ),
            },
            "capabilities": metric(
                capabilities["tp"], capabilities["fp"], capabilities["fn"]
            ),
            "behavior_chains": metric(
                behavior_chains["tp"], behavior_chains["fp"], behavior_chains["fn"]
            ),
            "interprocedural_behavior_chains": metric(
                interprocedural["tp"], interprocedural["fp"], interprocedural["fn"]
            ),
            "architecture_label_agreement": {
                "matching_pairs": pair_agreement,
                "total_pairs": len(results),
                "rate": pair_agreement / len(results),
            },
        },
        "limitations": resolved["limitations"],
        "results": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"analyzer corpus {report['status']}: {len(results)} cases, "
        f"{report['summary']['objects']} objects, {mismatches} mismatches"
    )
    print(f"report: {output_path.relative_to(root)}")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
