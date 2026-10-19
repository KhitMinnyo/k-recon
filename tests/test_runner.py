import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from k_recon.models import ModuleResult
from k_recon.runner import ScanInterrupted, resolve_plan, run_scan
from k_recon.scope import Scope


class RunnerTests(unittest.TestCase):
    def test_module_dependencies_are_added_in_order(self):
        self.assertEqual(resolve_plan(["http"]), ["discovery", "dns", "http"])
        self.assertEqual(resolve_plan(["screenshots", "urls"]), ["discovery", "dns", "http", "screenshots", "urls"])

    def test_unknown_modules_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown module"):
            resolve_plan(["not-a-module"])

    def test_failure_skips_dependent_modules_and_preserves_report(self):
        with TemporaryDirectory() as temporary:
            def fail(context):
                return ModuleResult("discovery", "failed", "mock failure")

            with patch.dict("k_recon.runner.MODULES", {"discovery": fail}):
                run_dir, results = run_scan("example.com", Scope.create(["example.com"]), Path(temporary), ["http"], 1, 1, False)
            self.assertEqual([result.state for result in results], ["failed", "skipped", "skipped"])
            self.assertTrue((run_dir / "report.json").is_file())
            self.assertTrue((run_dir / "logs" / "recon.log").is_file())

    def test_interrupt_writes_partial_report_and_skips_pending_modules(self):
        with TemporaryDirectory() as temporary:
            def interrupt(context):
                raise KeyboardInterrupt

            with patch.dict("k_recon.runner.MODULES", {"discovery": interrupt}):
                with self.assertRaises(ScanInterrupted) as raised:
                    run_scan("example.com", Scope.create(["example.com"]), Path(temporary), ["http"], 1, 1, False)
            report_path = raised.exception.run_dir / "report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["interrupted"])
            self.assertEqual([item["state"] for item in report["modules"]], ["skipped", "skipped", "skipped"])


if __name__ == "__main__":
    unittest.main()
