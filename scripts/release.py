#!/usr/bin/env python3
"""Verify the workspace package by default; --publish publishes missing versions in order."""

import argparse
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
ORDER = (
    "komainu-domain",
    "komainu-application",
    "komainu-adapter-std",
    "komainu-testkit",
    "komainu-adapter-postgres",
    "komainu-http",
    "komainu",
    "komainu-server",
)


def published(name, version):
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        headers={"User-Agent": "komainu-release (https://github.com/ryoshrimp/komainu)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise
    if data["version"]["yanked"]:
        raise RuntimeError(f"{name} {version} is yanked; choose a new version")
    return True


def release(publish=False):
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=ROOT, text=True,
    ))
    packages = {p["name"]: p for p in metadata["packages"]
                if p["id"] in metadata["workspace_members"]}
    # Validate the entire plan before starting any irreversible operation.
    plan = [(name, packages[name]["version"]) for name in ORDER]
    for name, version in plan:
        print(f"{name} {version}", flush=True)
    if not publish:
        # The crates depend on each other at the unpublished version, so only a
        # multi-package dry-run (verified against a local overlay) can succeed.
        subprocess.run(["cargo", "publish", "--workspace", "--dry-run", "--locked"],
                       cwd=ROOT, check=True)
        return
    for name, version in plan:
        if published(name, version):
            print(f"Skipping already published {name} {version}", flush=True)
            continue
        # Cargo waits for registry availability before the next dependent crate.
        subprocess.run(["cargo", "publish", "--locked", "-p", name], cwd=ROOT, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true",
                        help="actually publish to crates.io (requires a token)")
    args = parser.parse_args()
    release(args.publish)
