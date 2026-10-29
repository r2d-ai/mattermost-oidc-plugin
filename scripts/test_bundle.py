#!/usr/bin/env python3
"""Validate the archive layout consumed by Mattermost's plugin installer."""
import json
from pathlib import PurePosixPath
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    members = {member.name.removeprefix("./"): member for member in archive.getmembers()}
    assert "plugin.json" in members, "plugin.json must be at archive root"
    manifest = json.load(archive.extractfile(members["plugin.json"]))
    required = list(manifest["server"]["executables"].values())
    required += [manifest["webapp"]["bundle_path"], manifest["icon_path"]]
    allowed_files = {"plugin.json", *required}
    allowed_dirs = {str(parent) for path in allowed_files for parent in PurePosixPath(path).parents if str(parent) != "."}
    for name, member in members.items():
        assert (member.isfile() and name in allowed_files) or (member.isdir() and name.rstrip("/") in allowed_dirs), f"unexpected archive member: {name}"
    assert len(members) == len(archive.getmembers()), "duplicate archive members"
    for path in required:
        assert path in members and members[path].isfile(), f"missing manifest artifact: {path}"
        assert members[path].size > 0, f"empty artifact: {path}"
    assert all(not name.startswith(manifest["id"] + "/") for name in members), "nested plugin root"
    assert all(not member.issym() and not member.islnk() for member in members.values()), "unexpected link"
print("PASS: root manifest and all declared plugin artifacts")
