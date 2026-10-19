import unittest
from unittest.mock import patch

from k_recon.modules import screenshots
from k_recon.modules.base import ToolRun
from tests.helpers import make_context


class ScreenshotTests(unittest.TestCase):
    def test_only_passes_in_scope_non_redirect_urls_to_gowitness(self):
        context, temporary = make_context(".")
        self.addCleanup(temporary.cleanup)
        context.data["services"] = [
            {"url": "https://example.com/", "host": "example.com", "status_code": 200},
            {"url": "https://example.com/redirect", "host": "example.com", "status_code": 302},
            {"url": "https://notexample.com/", "host": "notexample.com", "status_code": 200},
        ]
        with patch("k_recon.modules.screenshots.run_tool", return_value=ToolRun()) as tool:
            result = screenshots.run(context)
        self.assertEqual(result.state, "success")
        targets = context.storage.path("screenshots/targets.txt").read_text(encoding="utf-8")
        self.assertEqual(targets, "https://example.com/\n")
        self.assertEqual(tool.call_args.args[0], "gowitness")
        self.assertIn("--file", tool.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
