#!/usr/bin/env python3
"""Audit the bus's normal/build closure using resolved Cargo package identities."""
import json
import subprocess
import sys

ALLOWED = {
    "serde", "serde_core", "serde_derive", "serde_json", "thiserror",
    "thiserror-impl", "proc-macro2", "quote", "syn", "unicode-ident",
    "itoa", "memchr", "zmij",
}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def audit(metadata):
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [package["id"] for package in metadata["packages"] if package["name"] == "tinywallet-bus"]
    if len(roots) != 1:
        raise ValueError("expected exactly one tinywallet-bus package")
    queue = [(roots[0], ["tinywallet-bus"])]
    seen = set()
    violations = []
    while queue:
        identity, path = queue.pop()
        if identity in seen:
            continue
        seen.add(identity)
        package = packages[identity]
        if len(path) > 1 and (package["name"] not in ALLOWED or package.get("source") != REGISTRY):
            violations.append(" -> ".join(path))
        for dependency in nodes[identity]["deps"]:
            if any(kind["kind"] in (None, "build") for kind in dependency["dep_kinds"]):
                child = dependency["pkg"]
                queue.append((child, path + [packages[child]["name"]]))
    return violations


if __name__ == "__main__":
    for features in ([], ["--all-features"]):
        result = subprocess.run(["cargo", "metadata", "--format-version", "1", *features], check=True, capture_output=True, text=True)
        failures = audit(json.loads(result.stdout))
        if failures:
            print("Forbidden contract dependencies:\n" + "\n".join(failures), file=sys.stderr)
            sys.exit(1)
    print("tinywallet-bus: default/all-feature normal/build closures are pure")
