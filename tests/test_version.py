"""The reported version must match the packaged version.

SDK_VERSION goes out in the User-Agent on every risk call, so if it drifts from
the distribution version, support reads the wrong SDK version off a client's
traffic. 1.0.1 shipped with that drift; this test exists so it cannot recur.
"""

from __future__ import annotations

import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from traitx import SDK_VERSION  # noqa: E402


class VersionTest(unittest.TestCase):
    def test_sdk_version_matches_pyproject(self) -> None:
        pyproject = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
        match = re.search(r'^version = "([^"]+)"', pyproject.read_text(), re.M)
        self.assertIsNotNone(match, "no version found in pyproject.toml")
        self.assertEqual(
            SDK_VERSION,
            match.group(1),
            "traitx.SDK_VERSION and pyproject.toml version have drifted",
        )


if __name__ == "__main__":
    unittest.main()
