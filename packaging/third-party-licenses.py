#!/usr/bin/env python3
"""Writes the license notices of every crate compiled into the release.

The library and CLI link their Rust dependencies statically, so shipping
them means shipping those crates' copyright and license texts too. This
walks Cargo's resolved dependency graph from this crate, for every
architecture the packages are built for and with every feature enabled
(what the packages build), along normal dependencies only. Covering all
of those architectures, not just the host's, keeps the output identical
across them, which Debian's Multi-Arch: same packages require. Build
scripts' dependencies, dev-dependencies and proc-macro crates run at
compile time and are left out: none of their code is in the binaries.

Usage: third-party-licenses.py OUTPUT_FILE
       third-party-licenses.py --licenses   (the distinct license expressions, one per line)

Needs only the dependency sources already fetched (`cargo fetch`); runs
offline.
"""

import json
import os
import re
import subprocess
import sys

LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|UNLICENSE|COPYRIGHT)([-._].*)?$", re.IGNORECASE)


# Keep in step with the architectures in debian/control and the RPM spec.
PACKAGED_TARGETS = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]


def linked_packages():
    platforms = [arg for target in PACKAGED_TARGETS for arg in ("--filter-platform", target)]
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--all-features", *platforms],
        check=True, capture_output=True, text=True).stdout)
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = meta["resolve"]["root"]

    def is_proc_macro(pkg):
        return any("proc-macro" in t["kind"] for t in pkg["targets"])

    seen, stack = set(), [root]
    while stack:
        node = nodes[stack.pop()]
        for dep in node["deps"]:
            if not any(k["kind"] is None for k in dep["dep_kinds"]):
                continue  # build- or dev-only edge
            if dep["pkg"] in seen or is_proc_macro(packages[dep["pkg"]]):
                continue
            seen.add(dep["pkg"])
            stack.append(dep["pkg"])
    return sorted((packages[i] for i in seen), key=lambda p: (p["name"], p["version"]))


def license_texts(pkg):
    crate_dir = os.path.dirname(pkg["manifest_path"])
    paths = sorted(os.path.join(crate_dir, f) for f in os.listdir(crate_dir) if LICENSE_FILE.match(f))
    if pkg.get("license_file"):
        declared = os.path.join(crate_dir, pkg["license_file"])
        if declared not in paths:
            paths.append(declared)
    return [(os.path.basename(p), open(p, encoding="utf-8", errors="replace").read()) for p in paths
            if os.path.isfile(p)]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    pkgs = linked_packages()
    if sys.argv[1] == "--licenses":
        for expr in sorted({p["license"] or "(see crate)" for p in pkgs}):
            print(expr)
        return
    with open(sys.argv[1], "w", encoding="utf-8") as out:
        out.write("Third-party software compiled into HKDFGuard\n"
                  "============================================\n\n"
                  "The HKDFGuard library and hkdfguard-v1-initialize statically link the\n"
                  "Rust crates below. Each is distributed under the license(s) shown,\n"
                  "followed by the license and notice files from that crate's sources.\n")
        for pkg in pkgs:
            out.write(f"\n{'=' * 72}\n{pkg['name']} {pkg['version']}\n"
                      f"License: {pkg['license'] or '(see files below)'}\n")
            if pkg.get("repository"):
                out.write(f"Source: {pkg['repository']}\n")
            texts = license_texts(pkg)
            if not texts:
                out.write("(This crate ships no license file; its license is the SPDX expression above.)\n")
            for name, text in texts:
                out.write(f"\n--- {name} ---\n\n{text.rstrip()}\n")


if __name__ == "__main__":
    main()
