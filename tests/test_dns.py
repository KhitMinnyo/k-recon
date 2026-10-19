import unittest
from types import SimpleNamespace
from unittest.mock import patch

import dns.exception as dns_exception

from k_recon.modules import dns
from tests.helpers import make_context


class FakeAnswer(list):
    def __init__(self, addresses):
        super().__init__(SimpleNamespace(address=address) for address in addresses)
        self.rrset = self or None


class DnsTests(unittest.TestCase):
    def test_private_address_prevents_network_module_eligibility(self):
        def resolve(_host, record_type, **_kwargs):
            answers = {"A": ["8.8.8.8"], "AAAA": ["fd00::1"]}[record_type]
            return FakeAnswer(answers)

        with patch("k_recon.modules.dns.dns.resolver.Resolver") as resolver_class:
            resolver_class.return_value.resolve.side_effect = resolve
            record = dns._resolve("example.com", 1)
        self.assertEqual(record["public_addresses"], ["8.8.8.8"])
        self.assertFalse(record["safe_for_network_modules"])

    def test_timeout_is_recorded_and_empty_answers_are_not_safe(self):
        def resolve(_host, record_type, **_kwargs):
            if record_type == "A":
                raise dns_exception.Timeout("mock timeout")
            return FakeAnswer([])

        with patch("k_recon.modules.dns.dns.resolver.Resolver") as resolver_class:
            resolver_class.return_value.resolve.side_effect = resolve
            record = dns._resolve("example.com", 1)
        self.assertEqual(record["errors"], ["A: Timeout"])
        self.assertFalse(record["safe_for_network_modules"])

    def test_records_safe_hosts_and_rejects_out_of_scope_names(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        context.data["hosts"] = ["example.com", "notexample.com"]
        with patch("k_recon.modules.dns._resolve", return_value={
            "host": "example.com",
            "addresses": ["8.8.8.8"],
            "public_addresses": ["8.8.8.8"],
            "safe_for_network_modules": True,
            "errors": [],
        }) as resolver:
            result = dns.run(context)
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(result.details["resolved"], 1)
        self.assertEqual(context.data["safe_hosts"], ["example.com"])


if __name__ == "__main__":
    unittest.main()
