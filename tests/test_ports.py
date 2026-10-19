import unittest
from unittest.mock import patch

from k_recon.modules import ports
from k_recon.modules.base import ToolRun
from k_recon.scope import Scope
from tests.helpers import make_context


class PortTests(unittest.TestCase):
    def test_skips_without_explicit_enable_flag(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        with patch("k_recon.modules.ports.run_tool") as tool:
            result = ports.run(context)
        tool.assert_not_called()
        self.assertEqual(result.state, "skipped")

    def test_scans_only_explicitly_allowlisted_resolved_ips(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        context.enable_nmap = True
        context.scope = Scope.create(["example.com"], include_ips=["8.8.8.8/32"])
        context.data["dns_records"] = [{
            "host": "example.com",
            "safe_for_network_modules": True,
            "public_addresses": ["8.8.8.8", "1.1.1.1"],
        }]
        with patch("k_recon.modules.ports.run_tool", return_value=ToolRun()) as tool:
            result = ports.run(context)
        args = tool.call_args.args[1]
        target_file = args[args.index("-iL") + 1]
        with open(target_file, encoding="utf-8") as targets:
            self.assertEqual(targets.read(), "8.8.8.8\n")
        self.assertEqual(result.details["targets"], 1)

    def test_reports_nmap_execution_failure(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        context.enable_nmap = True
        context.scope = Scope.create(["example.com"], include_ips=["8.8.8.8"])
        context.data["dns_records"] = [{
            "host": "example.com",
            "safe_for_network_modules": True,
            "public_addresses": ["8.8.8.8"],
        }]
        with patch("k_recon.modules.ports.run_tool", return_value=ToolRun(error="nmap is not installed", missing=True)):
            result = ports.run(context)
        self.assertEqual(result.state, "failed")
        self.assertIn("not installed", result.message)


if __name__ == "__main__":
    unittest.main()
