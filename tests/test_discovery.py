import unittest
from unittest.mock import patch

from k_recon.modules import discovery
from k_recon.modules.base import ToolRun
from tests.helpers import make_context


class DiscoveryTests(unittest.TestCase):
    def test_filters_each_provider_and_deduplicates_master_list(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        outputs = {
            "subfinder": ToolRun("api.example.com\nnotexample.com\n"),
            "assetfinder": ToolRun("api.example.com\nwww.example.com\n"),
            "amass": ToolRun("bad input\n"),
        }
        with patch("k_recon.modules.discovery.run_tool", side_effect=lambda name, *args: outputs[name]):
            result = discovery.run(context)
        self.assertEqual(result.state, "success")
        self.assertEqual(context.data["hosts"], ["api.example.com", "example.com", "www.example.com"])
        self.assertEqual(context.storage.path("subdomains/subfinder.txt").read_text(), "api.example.com\n")

    def test_missing_optional_tools_are_reported_without_stopping_seed_target(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        with patch("k_recon.modules.discovery.run_tool", return_value=ToolRun(error="not installed", missing=True)):
            result = discovery.run(context)
        self.assertEqual(result.state, "partial")
        self.assertEqual(context.data["hosts"], ["example.com"])
        self.assertEqual(result.details["providers"]["amass"]["state"], "missing")

    def test_successful_provider_keeps_module_success_with_missing_optional_providers(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)

        def one_provider(name, *_args):
            return ToolRun("api.example.com\n") if name == "subfinder" else ToolRun(error=f"{name} missing", missing=True)

        with patch("k_recon.modules.discovery.run_tool", side_effect=one_provider):
            result = discovery.run(context)
        self.assertEqual(result.state, "success")
        self.assertEqual(result.details["providers"]["assetfinder"]["state"], "missing")


if __name__ == "__main__":
    unittest.main()
