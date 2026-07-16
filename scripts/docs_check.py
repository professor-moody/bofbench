#!/usr/bin/env python3
import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


def slug(text: str) -> str:
    text = re.sub(r"[`*_]", "", text.strip().lower())
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    return re.sub(r"[\s-]+", "-", text).strip("-")


def check_tree(root: Path, docs: Path, errors: list[str]) -> str:
    combined = []
    markdown = sorted(docs.rglob("*.md"))
    for page in markdown:
        text = page.read_text(encoding="utf-8")
        combined.append(text)
        anchors = {slug(line.lstrip("#")) for line in text.splitlines() if line.startswith("#")}
        for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text):
            target = target.strip().strip("<>")
            if not target or target.startswith(("http://", "https://", "mailto:", "app://")):
                continue
            path_part, _, anchor = target.partition("#")
            disk = page if not path_part else (page.parent / path_part).resolve()
            if path_part and not disk.exists():
                errors.append(f"{page}: missing link target {target}")
                continue
            if anchor and disk.suffix.lower() == ".md":
                target_text = disk.read_text(encoding="utf-8")
                target_anchors = {slug(line.lstrip("#")) for line in target_text.splitlines() if line.startswith("#")}
                if anchor not in target_anchors:
                    errors.append(f"{page}: missing anchor {target}")
        for target in re.findall(r"(?:src|poster)=[\"']([^\"']+)[\"']", text):
            if target.startswith(("http://", "https://")):
                continue
            disk = (page.parent / target).resolve()
            if not disk.exists() and "assets/" in target:
                disk = docs / "assets" / target.split("assets/", 1)[1]
            if not disk.exists():
                errors.append(f"{page}: missing media {target}")
    joined = "\n".join(combined)
    prohibited = {
        r"\bcompetition\b": "competition framing",
        r"\bjudge-facing\b": "judge-facing framing",
        r"\bpresentation-production\b": "presentation-production framing",
    }
    for pattern, description in prohibited.items():
        if re.search(pattern, joined, re.IGNORECASE):
            errors.append(f"{docs}: contains prohibited stale {description}")
    return joined


def png_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()[:24]
    if len(data) != 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    return struct.unpack(">II", data[16:24])


def check_media(root: Path, errors: list[str]) -> None:
    expected = {
        "build-analyze",
        "third-party-analysis",
        "arsenal-search",
        "lab-run",
        "runtime-tasks",
        "export-verify",
        "operation-lifecycle",
    }
    tapes = {path.stem: path for path in (root / "docs/media-src").glob("*.tape")}
    videos = {path.stem: path for path in (root / "docs/assets/media").glob("*.webm")}
    posters = {path.stem: path for path in (root / "docs/assets/images").glob("*.png")}
    for kind, actual in (("tape", set(tapes)), ("WebM", set(videos)), ("poster", set(posters))):
        missing = expected - actual
        if missing:
            errors.append(f"documentation media is missing {kind}: {', '.join(sorted(missing))}")
    for stem in sorted(expected & set(tapes)):
        tape_text = tapes[stem].read_text(encoding="utf-8")
        for directive, want in (("Width", "1280"), ("Height", "720")):
            if not re.search(rf"^Set {directive} \"?{want}\"?$", tape_text, re.MULTILINE):
                errors.append(f"{tapes[stem]}: expected {directive} {want}")
        speed = re.search(r"^Set TypingSpeed (\d+)ms$", tape_text, re.MULTILINE)
        if not speed or not 35 <= int(speed.group(1)) <= 45:
            errors.append(f"{tapes[stem]}: typing speed must be 35-45ms")
        if f"Output docs/assets/media/{stem}.webm" not in tape_text:
            errors.append(f"{tapes[stem]}: output does not match checked-in WebM")
        for line in tape_text.splitlines():
            if line.startswith("Type ") and "bofbench" not in line:
                errors.append(f"{tapes[stem]}: terminal capture types a non-BOFBench command: {line}")
    for stem in sorted(expected & set(posters)):
        try:
            if png_dimensions(posters[stem]) != (1280, 720):
                errors.append(f"{posters[stem]}: poster must be 1280x720")
        except ValueError as exc:
            errors.append(f"{posters[stem]}: {exc}")
    ffprobe = shutil.which("ffprobe")
    if ffprobe:
        for stem in sorted(expected & set(videos)):
            try:
                raw = subprocess.check_output(
                    [ffprobe, "-v", "error", "-show_entries", "stream=width,height:format=duration", "-of", "json", str(videos[stem])],
                    text=True,
                )
                metadata = json.loads(raw)
                stream = metadata["streams"][0]
                duration = float(metadata["format"]["duration"])
                if (stream.get("width"), stream.get("height")) != (1280, 720):
                    errors.append(f"{videos[stem]}: video must be 1280x720")
                if not 0 < duration <= 45:
                    errors.append(f"{videos[stem]}: duration {duration:.2f}s exceeds 45s")
            except (KeyError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
                errors.append(f"{videos[stem]}: cannot read media metadata: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--bin", required=True)
    parser.add_argument("--private")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors: list[str] = []
    public_text = check_tree(root, root / "docs", errors)

    help_text = subprocess.check_output([args.bin, "--help"], text=True)
    commands = set(re.findall(r"^  ([a-z][a-z-]+)\s{2,}", help_text, re.MULTILINE)) - {"help", "completion"}
    for command in sorted(commands):
        if not re.search(rf"\bbofbench\s+{re.escape(command)}\b|`{re.escape(command)}`", public_text):
            errors.append(f"public docs do not cover top-level command {command}")

    public_reference = (root / "docs/pack-reference.md").read_text(encoding="utf-8")
    public_ids = set(re.findall(r"^## `builtin/([^`]+)`", public_reference, re.MULTILINE))
    public_count = len(public_ids)
    if public_count != 84:
        errors.append(f"public pack reference count is {public_count}, expected 84")

    public_operation_reference = (root / "docs/operation-reference.md").read_text(encoding="utf-8")
    public_operation_ids = set(
        re.findall(r"^## `builtin/([^`]+)`", public_operation_reference, re.MULTILINE)
    )
    if len(public_operation_ids) != 6:
        errors.append(
            f"public operation reference count is {len(public_operation_ids)}, expected 6"
        )

    check_media(root, errors)

    known_output_tags = public_ids | {"host", "environment-value"}
    if args.private:
        private = Path(args.private).resolve()
        private_text = check_tree(private, private / "docs", errors)
        private_reference = (private / "PACK_REFERENCE.md").read_text(encoding="utf-8")
        private_ids = set(re.findall(r"^## `bofbench-packs-internal/([^`]+)`", private_reference, re.MULTILINE))
        private_count = len(private_ids)
        if private_count != 134:
            errors.append(f"private pack reference count is {private_count}, expected 134")
        private_operation_reference = (private / "OPERATION_REFERENCE.md").read_text(
            encoding="utf-8"
        )
        private_operation_ids = set(
            re.findall(
                r"^## `bofbench-packs-internal/([^`]+)`",
                private_operation_reference,
                re.MULTILINE,
            )
        )
        if len(private_operation_ids) != 30:
            errors.append(
                f"private operation reference count is {len(private_operation_ids)}, expected 30"
            )
        known_output_tags |= private_ids
        for manifest in private.glob("*/pack.json"):
            pack_id = manifest.parent.name
            if pack_id not in private_text and pack_id not in private_reference:
                errors.append(f"private handbook/reference does not mention {pack_id}")

    scenario_text = "\n".join(path.read_text(encoding="utf-8") for path in (root / "docs/scenarios").glob("*.md"))
    output_tags = set(re.findall(r"^\s*\[([a-z0-9][a-z0-9-]+)\]", scenario_text, re.MULTILINE))
    unknown_tags = output_tags - known_output_tags
    if unknown_tags:
        errors.append(f"scenario output tags are not backed by a pack contract: {', '.join(sorted(unknown_tags))}")

    if errors:
        print("documentation validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("documentation structure validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
