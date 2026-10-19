import contextlib
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from k_recon.cli import main
from k_recon.models import ModuleResult


class CliTests(unittest.TestCase):
    def test_scan_requires_authorization_confirmation(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["scan", "--domain", "example.com"])
        self.assertEqual(raised.exception.code, 2)

    def test_ports_require_explicit_nmap_opt_in(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["scan", "--domain", "example.com", "--modules", "ports", "--authorized"])
        self.assertEqual(raised.exception.code, 2)

    def test_timeout_must_be_finite_and_positive(self):
        for timeout in ("0", "nan", "inf"):
            with self.subTest(timeout=timeout), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["scan", "--domain", "example.com", "--authorized", "--timeout", timeout])
                self.assertEqual(raised.exception.code, 2)

    def test_tools_command_lists_optional_tools_without_network_access(self):
        with patch("k_recon.cli.tool_available", return_value=False), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["tools"]), 0)

    def test_readme_scan_command_matches_parser_and_runner_arguments(self):
        with TemporaryDirectory() as temporary:
            scope_path = Path(temporary) / "scope.yaml"
            scope_path.write_text("scope:\n  include: [example.com]\n", encoding="utf-8")
            with (
                patch("k_recon.cli.run_scan", return_value=(Path(temporary) / "run", [ModuleResult("http", "success", "ok")] )) as run_scan,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = main([
                    "scan", "--domain", "example.com", "--scope", str(scope_path),
                    "--modules", "discovery,dns,http", "--authorized", "--timeout", "10", "--workers", "8",
                ])
        self.assertEqual(result, 0)
        self.assertEqual(run_scan.call_args.args[3], ["discovery", "dns", "http"])
        self.assertEqual(run_scan.call_args.args[4:6], (10.0, 8))

    def test_readme_nmap_command_passes_explicit_opt_in(self):
        with TemporaryDirectory() as temporary:
            scope_path = Path(temporary) / "scope.yaml"
            scope_path.write_text("scope:\n  include: [example.com]\n  include_ips: [8.8.8.8]\n", encoding="utf-8")
            with (
                patch("k_recon.cli.run_scan", return_value=(Path(temporary) / "run", [])) as run_scan,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = main([
                    "scan", "--domain", "example.com", "--scope", str(scope_path),
                    "--modules", "discovery,dns", "--enable-nmap", "--authorized",
                ])
        self.assertEqual(result, 0)
        self.assertIn("ports", run_scan.call_args.args[3])
        self.assertTrue(run_scan.call_args.args[6])


if __name__ == "__main__":
    unittest.main()
