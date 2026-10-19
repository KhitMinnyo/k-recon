import unittest

from k_recon.scope import Scope, normalize_domain


class ScopeTests(unittest.TestCase):
    def test_normalizes_unicode_and_case(self):
        self.assertEqual(normalize_domain("BÜCHER.Example."), "xn--bcher-kva.example")

    def test_rejects_ip_and_malformed_names(self):
        for value in ("127.0.0.1", "example.com/path", "example.com:443", "https://example.com:/", "localhost", "-bad.example"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)

    def test_uses_dns_label_boundaries(self):
        scope = Scope.create(["example.com"])
        self.assertTrue(scope.allows("example.com"))
        self.assertTrue(scope.allows("api.example.com"))
        self.assertFalse(scope.allows("notexample.com"))
        self.assertFalse(scope.allows("example.com.attacker.test"))

    def test_validates_url_scheme_credentials_port_and_scope(self):
        scope = Scope.create(["example.com"])
        self.assertTrue(scope.allows_url("https://api.example.com:8443/path"))
        for value in (
            "ftp://example.com/file",
            "https://user:secret@example.com/",
            "https://example.com:/",
            "https://example.com:0/",
            "https://example.com:99999/",
            "https://notexample.com/",
        ):
            with self.subTest(value=value):
                self.assertFalse(scope.allows_url(value))

    def test_exclusions_apply_to_nested_domains(self):
        scope = Scope.create(["example.com"], ["private.example.com"])
        self.assertFalse(scope.allows("private.example.com"))
        self.assertFalse(scope.allows("dev.private.example.com"))
        self.assertTrue(scope.allows("public.example.com"))

    def test_exclusion_must_belong_to_an_included_root(self):
        with self.assertRaises(ValueError):
            Scope.create(["example.com"], ["example.org"])

    def test_nmap_ip_requires_explicit_public_scope(self):
        scope = Scope.create(["example.com"], include_ips=["203.0.113.0/24"])
        self.assertFalse(scope.allows_ip("203.0.113.4"))
        scope = Scope.create(["example.com"], include_ips=["8.8.8.0/24"])
        self.assertTrue(scope.allows_ip("8.8.8.8"))
        self.assertFalse(scope.allows_ip("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
