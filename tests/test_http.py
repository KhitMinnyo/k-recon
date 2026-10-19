import json
import unittest
from unittest.mock import patch

from k_recon.modules import http
from k_recon.modules.base import ToolRun
from k_recon.scope import Scope
from tests.helpers import make_context


class HttpTests(unittest.TestCase):
    def test_httpx_results_are_scope_filtered(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        context.scope = Scope.create(["example.com"], include_ips=["8.8.8.8"])
        context.data["dns_records"] = [{"host": "example.com", "safe_for_network_modules": True, "public_addresses": ["8.8.8.8"]}]
        payload = "\n".join([
            json.dumps({"url": "https://example.com/", "status_code": 200, "title": "Example"}),
            json.dumps({"url": "https://notexample.com/", "status_code": 200}),
            json.dumps({"url": "https://user:secret@example.com/", "status_code": 200}),
        ])
        with (
            patch("k_recon.modules.http.tool_available", return_value=True),
            patch("k_recon.modules.http.run_tool", return_value=ToolRun(payload)) as tool,
        ):
            result = http.run(context)
        self.assertEqual(tool.call_args.args[0], "httpx")
        args = tool.call_args.args[1]
        self.assertEqual(args[args.index("-allow") + 1], "8.8.8.8/32")
        self.assertEqual(result.details["live"], 1)
        self.assertEqual(context.data["live_urls"], ["https://example.com/"])

    def test_uses_pinned_probe_when_ips_are_not_explicitly_authorized_for_httpx(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        context.data["dns_records"] = [{"host": "example.com", "safe_for_network_modules": True, "public_addresses": ["8.8.8.8"]}]
        with (
            patch("k_recon.modules.http.tool_available") as available,
            patch("k_recon.modules.http._native_probe", return_value=http.Service("https://example.com/", "example.com", 200, "Example")),
        ):
            result = http.run(context)
        available.assert_not_called()
        self.assertEqual(result.details["live"], 1)
        self.assertEqual(result.state, "success")


if __name__ == "__main__":
    unittest.main()
