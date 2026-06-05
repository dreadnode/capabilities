#!/usr/bin/env python3
"""Plan GitHub Releases for changed capability manifest versions.

The capabilities repository is a monorepo: each capability owns its own
``capability.yaml`` version. This script maps a git commit range to the set of
capability-scoped tags that should become GitHub Releases.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass


MANIFEST_RE = re.compile(r"^capabilities/([^/]+)/capability\.yaml$")
FIELD_RE = re.compile(r"^(?P<key>name|version):\s*(?P<value>.+?)\s*(?:#.*)?$")


@dataclass(frozen=True)
class CapabilityRelease:
    capability: str
    version: str
    tag: str
    title: str
    previous_tag: str | None = None


def run_git(args: list[str], *, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def clean_yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_manifest(text: str) -> tuple[str | None, str | None]:
    name: str | None = None
    version: str | None = None
    for raw_line in text.splitlines():
        match = FIELD_RE.match(raw_line)
        if not match:
            continue
        key = match.group("key")
        value = clean_yaml_scalar(match.group("value"))
        if key == "name":
            name = value
        elif key == "version":
            version = value
    return name, version


def read_file_at(ref: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def changed_manifest_paths(base: str, head: str) -> list[str]:
    output = run_git(["diff", "--name-only", base, head, "--", "capabilities"])
    paths = []
    for line in output.splitlines():
        if MANIFEST_RE.match(line):
            paths.append(line)
    return sorted(set(paths))


def tag_exists(tag: str) -> bool:
    return bool(run_git(["tag", "--list", tag]).strip())


def previous_capability_tag(capability: str, current_tag: str) -> str | None:
    pattern = f"capability/{capability}/v*"
    output = run_git(
        [
            "for-each-ref",
            "--sort=-creatordate",
            "--format=%(refname:short)",
            f"refs/tags/{pattern}",
        ]
    )
    for tag in output.splitlines():
        if tag and tag != current_tag:
            return tag
    return None


def build_release_plan(base: str, head: str) -> list[CapabilityRelease]:
    releases: list[CapabilityRelease] = []

    for path in changed_manifest_paths(base, head):
        head_text = read_file_at(head, path)
        if head_text is None:
            continue

        manifest_name, new_version = parse_manifest(head_text)
        capability = manifest_name or MANIFEST_RE.match(path).group(1)  # type: ignore[union-attr]
        if not new_version:
            continue

        base_text = read_file_at(base, path)
        _old_name, old_version = (
            parse_manifest(base_text) if base_text else (None, None)
        )
        if old_version == new_version:
            continue

        tag = f"capability/{capability}/v{new_version}"
        if tag_exists(tag):
            continue

        releases.append(
            CapabilityRelease(
                capability=capability,
                version=new_version,
                tag=tag,
                title=f"{capability} v{new_version}",
                previous_tag=previous_capability_tag(capability, tag),
            )
        )

    return releases


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a GitHub Release plan for capability version changes."
    )
    parser.add_argument("base", help="Base commit/ref for the comparison")
    parser.add_argument("head", help="Head commit/ref for the comparison")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        releases = build_release_plan(args.base, args.head)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    json.dump({"releases": [asdict(release) for release in releases]}, sys.stdout)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
