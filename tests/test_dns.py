import unittest
from unittest.mock import patch

from k_recon.modules import dns
from tests.helpers import make_context


class DnsTests(unittest.TestCase):
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
