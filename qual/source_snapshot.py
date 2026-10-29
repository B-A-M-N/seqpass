#!/usr/bin/env python3
"""Create a deterministic manifest for the current SeqPass source worktree.

The digest covers regular files and symlink targets, including untracked and
ignored project files, while excluding Git internals, temporary test state,
qualification evidence, and local .opencode state. File permission bits are
included so executable source helpers remain part of the identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

EXCLUDED_DIRS = {".git", ".tmp", ".opencode"}
EXCLUDED_PATHS = {Path("qual/evidence")}
SCHEMA = "seqpass-source-snapshot/1"


def excluded(relative: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in relative.parts):
        return True
    return any(relative == path or path in relative.parents for path in EXCLUDED_PATHS)


def inventory(root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        symlink_dirs = [name for name in dirs if (current_path / name).is_symlink()]
        dirs[:] = sorted(
            name for name in dirs
            if not excluded((current_path / name).relative_to(root))
            and not (current_path / name).is_symlink()
        )
        candidates = sorted([*names, *symlink_dirs])
        for name in candidates:
            path = current_path / name
            relative = path.relative_to(root)
            if excluded(relative):
                continue
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISREG(info.st_mode):
                content_hash = hashlib.sha256()
                with path.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        content_hash.update(chunk)
                records.append({
                    "path": relative.as_posix(), "kind": "file", "mode": mode,
                    "size": info.st_size, "sha256": content_hash.hexdigest(),
                })
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                target_bytes = os.fsencode(target)
                records.append({
                    "path": relative.as_posix(), "kind": "symlink", "mode": mode,
                    "size": len(target_bytes), "target": target,
                    "sha256": hashlib.sha256(target_bytes).hexdigest(),
                })
    records.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return records


def tree_digest(records: list[dict[str, object]]) -> str:
    digest = hashlib.sha256(b"seqpass-source-snapshot-v1\0")
    for record in records:
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def git_identity(root: Path) -> tuple[str, bool]:
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
        check=True, capture_output=True, text=True,
    ).stdout
    return revision, bool(status.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True, help="new manifest path (mode 0600)")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    output = args.output.absolute()
    if not output.is_absolute() or output.exists():
        parser.error("--output must name a path that does not already exist")
    records = inventory(root)
    revision, dirty = git_identity(root)
    manifest = {
        "schema": SCHEMA,
        "source_revision": revision,
        "worktree_dirty": dirty,
        "snapshot_sha256": tree_digest(records),
        "snapshot_algorithm": "sha256(domain || sorted length-prefixed canonical JSON file records)",
        "excluded_paths": [".git/**", ".tmp/**", ".opencode/**", "qual/evidence/**"],
        "file_count": len(records),
        "files": records,
    }
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(output, 0o600)
    except BaseException:
        try:
            output.unlink()
        except OSError:
            pass
        raise
    print(json.dumps({key: manifest[key] for key in ("source_revision", "worktree_dirty", "snapshot_sha256", "file_count")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
