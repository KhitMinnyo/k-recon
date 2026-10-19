import unittest
from unittest.mock import patch

from k_recon.modules import urls
from k_recon.modules.base import ToolRun
from tests.helpers import make_context


class UrlTests(unittest.TestCase):
    def test_deduplicates_and_rejects_out_of_scope_urls(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        context.data["hosts"] = ["example.com", "api.example.com", "attacker.test"]
        output = "https://example.com/search?q=1\nhttps://example.com/app.js\nhttps://notexample.com/out\nhttps://user:secret@example.com/private\nhttps://example.com:bad/path\n"
        with patch("k_recon.modules.urls.run_tool", side_effect=[ToolRun(output), ToolRun(error="not installed", missing=True)]) as mocked:
            result = urls.run(context)
        self.assertEqual(mocked.call_args_list[0].args[3], "api.example.com\nexample.com\n")
        self.assertEqual(result.details["urls"], 2)
        self.assertEqual(result.state, "success")
        self.assertEqual(result.details["providers"]["gau"]["state"], "missing")
        self.assertEqual(context.data["parameters"], ["https://example.com/search?q="])
        self.assertEqual(context.storage.path("urls/extensions/js.txt").read_text(), "https://example.com/app.js\n")


if __name__ == "__main__":
    unittest.main()
