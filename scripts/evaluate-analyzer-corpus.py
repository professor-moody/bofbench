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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
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


def add_confusion(counter: Counter[str], expected: list[str], actual: list[str]) -> None:
    expected_set = set(expected)
    actual_set = set(actual)
    counter["tp"] += len(expected_set & actual_set)
    counter["fp"] += len(actual_set - expected_set)
    counter["fn"] += len(expected_set - actual_set)


def require_repo_path(root: Path, value: str, label: str) -> Path:
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        fail(f"{label} escapes the repository: {value}")
    return candidate


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
    corpus = load_json(corpus_path)
    if (
        corpus.get("schema") != "bofbench.analyzer-evaluation-corpus"
        or corpus.get("schema_version") != 1
        or corpus.get("state") != "labels_frozen"
    ):
        fail("corpus is not a frozen bofbench.analyzer-evaluation-corpus/v1")

    status = run_text(["git", "status", "--porcelain"], root)
    if status.strip():
        fail("evaluation requires a clean BOFBench checkout")
    source_commit = run_text(["git", "rev-parse", "HEAD"], root).strip()
    frozen_commit = run_text(
        ["git", "log", "-1", "--format=%H", "--", args.corpus], root
    ).strip()

    provenance = corpus.get("provenance", {})
    if not isinstance(provenance, dict):
        fail("corpus provenance is missing")
    lock_path = require_repo_path(root, str(provenance.get("object_lock", "")), "object lock")
    if sha256(lock_path) != provenance.get("object_lock_sha256"):
        fail("object lock digest does not match the frozen corpus")
    lock = load_json(lock_path)
    repositories = lock.get("repositories", [])
    if len(repositories) != 1 or not isinstance(repositories[0], dict):
        fail("object lock must contain exactly one repository")
    locked_repository = repositories[0]
    for field in ("name", "repository", "commit", "root"):
        if provenance.get(field) != locked_repository.get(field):
            fail(f"corpus provenance field {field} does not match the object lock")
    object_root = require_repo_path(root, str(provenance["root"]), "object root")
    locked_objects = {
        item["path"]: item["sha256"] for item in locked_repository.get("objects", [])
    }

    version = run_json([str(binary), "version", "--format", "json"], root)
    tool = version.get("tool", {})
    if not isinstance(tool, dict) or tool.get("commit") != source_commit:
        fail(
            f"binary commit {tool.get('commit') if isinstance(tool, dict) else ''} "
            f"does not match checkout {source_commit}"
        )
    inventory = run_json(
        [str(binary), "arsenal", "inventory", str(object_root), "--format", "json"],
        root,
    )
    signature_set = inventory.get("analyzer_signature_set")
    if not isinstance(signature_set, str) or len(signature_set) != 64:
        fail("arsenal inventory did not return an analyzer signature-set digest")

    support_counts: Counter[str] = Counter()
    capabilities: Counter[str] = Counter()
    behavior_chains: Counter[str] = Counter()
    interprocedural: Counter[str] = Counter()
    pair_agreement = 0
    results: list[dict[str, Any]] = []

    cases = corpus.get("cases", [])
    if not isinstance(cases, list) or not cases:
        fail("corpus has no cases")
    for case in cases:
        if not isinstance(case, dict):
            fail("corpus case must be an object")
        case_id = str(case.get("id", ""))
        objects = case.get("objects", {})
        expected_support = case.get("expected_support", {})
        labels = case.get("labels", {})
        if not all(isinstance(value, dict) for value in (objects, expected_support, labels)):
            fail(f"case {case_id} is malformed")
        expected_capabilities = exact_labels(labels.get("capabilities"), f"{case_id} capabilities")
        expected_chains = exact_labels(labels.get("behavior_chains"), f"{case_id} behavior chains")
        expected_interprocedural = exact_labels(
            labels.get("interprocedural_behavior_chains"),
            f"{case_id} interprocedural chains",
        )
        architectures: list[dict[str, Any]] = []
        actual_by_arch: dict[str, tuple[list[str], list[str], list[str]]] = {}
        for arch in ("x64", "x86"):
            relative = objects.get(arch)
            if not isinstance(relative, str) or relative not in locked_objects:
                fail(f"case {case_id} {arch} object is not in the frozen object lock")
            object_path = require_repo_path(object_root, relative, f"case {case_id} {arch} object")
            object_digest = sha256(object_path)
            if object_digest != locked_objects[relative]:
                fail(f"case {case_id} {arch} object digest mismatch")
            payload = run_json(
                [str(binary), "analyze", str(object_path), "--format", "json"], root
            )
            analysis = payload.get("analysis", {})
            if not isinstance(analysis, dict) or analysis.get("sha256") != object_digest:
                fail(f"case {case_id} {arch} analysis did not bind the object digest")
            actual_support = str(
                (analysis.get("loader_compatibility") or {}).get("status", "")
            )
            actual_capabilities = sorted(
                {str(item.get("id")) for item in analysis.get("capabilities", []) if item.get("id")}
            )
            chains = analysis.get("behavior_chains", [])
            actual_chains = sorted({str(item.get("id")) for item in chains if item.get("id")})
            actual_interprocedural = sorted(
                {
                    str(item.get("id"))
                    for item in chains
                    if item.get("id") and item.get("interprocedural") is True
                }
            )
            expected = str(expected_support.get(arch, ""))
            support_counts["total"] += 1
            support_counts["correct"] += int(actual_support == expected)
            support_counts["expected_" + expected] += 1
            add_confusion(capabilities, expected_capabilities, actual_capabilities)
            add_confusion(behavior_chains, expected_chains, actual_chains)
            add_confusion(interprocedural, expected_interprocedural, actual_interprocedural)
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
                "architecture_label_agreement": agrees,
                "status": (
                    "pass"
                    if agrees and all(item["status"] == "pass" for item in architectures)
                    else "mismatch"
                ),
                "architectures": architectures,
            }
        )

    mismatches = sum(item["status"] != "pass" for item in results)
    report = {
        "schema": "bofbench.analyzer-corpus-evaluation",
        "schema_version": 1,
        "status": "pass" if mismatches == 0 else "mismatch",
        "evaluated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "corpus": {
            "id": corpus.get("corpus_id"),
            "path": args.corpus,
            "sha256": sha256(corpus_path),
            "labels_frozen_commit": frozen_commit,
            "object_lock_sha256": sha256(lock_path),
            "upstream_commit": provenance.get("commit"),
        },
        "analyzer": {
            "source_commit": source_commit,
            "binary_sha256": sha256(binary),
            "tool": tool,
            "host": version.get("host"),
            "signature_set_sha256": signature_set,
        },
        "summary": {
            "cases": len(results),
            "objects": sum(len(item["architectures"]) for item in results),
            "mismatched_cases": mismatches,
            "loader_support": {
                "correct": support_counts["correct"],
                "total": support_counts["total"],
                "accuracy": support_counts["correct"] / support_counts["total"],
                "expected_classes": {
                    key.removeprefix("expected_"): value
                    for key, value in sorted(support_counts.items())
                    if key.startswith("expected_")
                },
                "blocked_recall": {
                    "state": "withheld",
                    "reason": "the frozen corpus has no loader-blocked object",
                },
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
        "limitations": corpus.get("limitations"),
        "results": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"analyzer corpus {report['status']}: {len(results)} cases, "
        f"{report['summary']['objects']} objects, {mismatches} mismatches"
    )
    print(f"report: {output_path.relative_to(root)}")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
