import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from k_recon.storage import RunStorage


class StorageTests(unittest.TestCase):
    def test_runs_are_unique_and_target_paths_are_normalized(self):
        with TemporaryDirectory() as temporary:
            first = RunStorage(Path(temporary), "EXAMPLE.com.")
            second = RunStorage(Path(temporary), "example.com")
            self.assertNotEqual(first.run_dir, second.run_dir)
            self.assertEqual(first.target_dir.name, "example.com")

    def test_writes_deduplicated_sorted_lines_and_json(self):
        with TemporaryDirectory() as temporary:
            store = RunStorage(Path(temporary), "example.com")
            file_path = store.write_lines("subdomains/all.txt", ["b.example.com", "a.example.com", "a.example.com"])
            self.assertEqual(file_path.read_text(encoding="utf-8"), "a.example.com\nb.example.com\n")
            store.write_json("report.json", {"ok": True})
            self.assertIn('"ok": true', store.path("report.json").read_text(encoding="utf-8"))

    def test_rejects_artifact_path_traversal(self):
        with TemporaryDirectory() as temporary:
            store = RunStorage(Path(temporary), "example.com")
            with self.assertRaises(ValueError):
                store.path("../outside.txt")


if __name__ == "__main__":
    unittest.main()
