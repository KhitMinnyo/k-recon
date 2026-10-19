import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from k_recon.config import load_scope


class ConfigTests(unittest.TestCase):
    def test_loads_allowlist_exclusions_and_ip_scope(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "scope.yaml"
            path.write_text(
                "scope:\n  include: [example.com]\n  exclude: [private.example.com]\n  include_ips: [8.8.8.8]\n",
                encoding="utf-8",
            )
            scope = load_scope(path, "api.example.com")
            self.assertTrue(scope.allows("api.example.com"))
            self.assertFalse(scope.allows("private.example.com"))
            self.assertTrue(scope.allows_ip("8.8.8.8"))

    def test_rejects_target_outside_configured_scope(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "scope.yaml"
            path.write_text("scope:\n  include: [example.com]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not allowed"):
                load_scope(path, "example.org")

    def test_defaults_to_target_scope(self):
        scope = load_scope(None, "api.example.com")
        self.assertTrue(scope.allows("api.example.com"))
        self.assertFalse(scope.allows("example.com"))


if __name__ == "__main__":
    unittest.main()
