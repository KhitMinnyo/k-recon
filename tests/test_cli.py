import contextlib
import io
import unittest
from unittest.mock import patch

from k_recon.cli import main


class CliTests(unittest.TestCase):
    def test_scan_requires_authorization_confirmation(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["scan", "--domain", "example.com"])
        self.assertEqual(raised.exception.code, 2)

    def test_ports_require_explicit_nmap_opt_in(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["scan", "--domain", "example.com", "--modules", "ports", "--authorized"])
        self.assertEqual(raised.exception.code, 2)

    def test_tools_command_lists_optional_tools_without_network_access(self):
        with patch("k_recon.cli.tool_available", return_value=False), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["tools"]), 0)


if __name__ == "__main__":
    unittest.main()
