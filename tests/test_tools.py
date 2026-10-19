import subprocess
import unittest
from unittest.mock import patch

from k_recon.modules.base import run_tool, tool_available


class ToolTests(unittest.TestCase):
    def test_invokes_commands_without_a_shell_and_checks_exit_status(self):
        completed = subprocess.CompletedProcess(["tool"], 0, "ok\n", "")
        with (
            patch("k_recon.modules.base.shutil.which", return_value="/usr/bin/tool"),
            patch("k_recon.modules.base.subprocess.run", return_value=completed) as process,
        ):
            result = run_tool("tool", ["--target", "a value"], 2, "input\n")
        self.assertEqual(result.output, "ok\n")
        self.assertEqual(process.call_args.args[0], ["/usr/bin/tool", "--target", "a value"])
        self.assertFalse(process.call_args.kwargs["shell"] if "shell" in process.call_args.kwargs else False)
        self.assertEqual(process.call_args.kwargs["timeout"], 2)

    def test_treats_python_httpx_cli_as_incompatible(self):
        completed = subprocess.CompletedProcess(["httpx", "-version"], 2, "", "No such option")
        with (
            patch("k_recon.modules.base.shutil.which", return_value="/usr/bin/httpx"),
            patch("k_recon.modules.base.subprocess.run", return_value=completed),
        ):
            self.assertFalse(tool_available("httpx"))

    def test_reports_tool_timeout_and_nonzero_exit(self):
        with (
            patch("k_recon.modules.base.shutil.which", return_value="/usr/bin/tool"),
            patch("k_recon.modules.base.subprocess.run", side_effect=subprocess.TimeoutExpired("tool", 1)),
        ):
            timeout_result = run_tool("tool", [], 1)
        self.assertIn("timeout", timeout_result.error)

        completed = subprocess.CompletedProcess(["tool"], 3, "partial", "failure detail")
        with (
            patch("k_recon.modules.base.shutil.which", return_value="/usr/bin/tool"),
            patch("k_recon.modules.base.subprocess.run", return_value=completed),
        ):
            failed_result = run_tool("tool", [], 1)
        self.assertEqual(failed_result.output, "partial")
        self.assertEqual(failed_result.error, "failure detail")


if __name__ == "__main__":
    unittest.main()
