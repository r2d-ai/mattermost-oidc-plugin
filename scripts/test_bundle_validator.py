#!/usr/bin/env python3
"""Exercise the archive validator against a flat bundle and an extra file."""
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


class BundleValidationTest(unittest.TestCase):
    def test_flat_bundle_and_unexpected_file(self):
        root = Path(__file__).resolve().parent.parent
        manifest = json.loads((root / "plugin.json").read_text())
        files = list(manifest["server"]["executables"].values())
        files += [manifest["webapp"]["bundle_path"], manifest["icon_path"]]
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle.tar.gz"
            for extra in (False, True):
                with tarfile.open(bundle, "w:gz") as archive:
                    contents = {"plugin.json": json.dumps(manifest).encode()}
                    contents.update({name: b"fixture" for name in files})
                    if extra:
                        contents["unexpected.txt"] = b"unexpected"
                    for name, data in contents.items():
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))
                result = subprocess.run(
                    ["python3", str(root / "scripts/test_bundle.py"), str(bundle)],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, not extra, result.stderr)


if __name__ == "__main__":
    unittest.main()
