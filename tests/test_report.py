import json
import os
import shutil
import tempfile
import unittest

from netpwn import report


class TestReport(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_generates_json_and_md(self):
        paths = report.generate_report(
            {"summary": {"modules": 5}}, path=self.dir)
        self.assertTrue(os.path.isfile(paths["json"]))
        self.assertTrue(os.path.isfile(paths["markdown"]))

    def test_json_content(self):
        paths = report.generate_report(
            {"summary": {"tests_passed": 30}}, path=self.dir)
        with open(paths["json"]) as f:
            data = json.load(f)
        self.assertEqual(data["summary"]["tests_passed"], 30)

    def test_md_contains_title(self):
        paths = report.generate_report(
            {"summary": {}}, title="netpwn Test Report", path=self.dir)
        with open(paths["markdown"]) as f:
            md = f.read()
        self.assertIn("# netpwn Test Report", md)

    def test_list_section(self):
        paths = report.generate_report(
            {"details": ["a", "b", "c"]}, path=self.dir)
        with open(paths["markdown"]) as f:
            md = f.read()
        self.assertIn("- a", md)
        self.assertIn("- c", md)

    def test_ensure_dirs(self):
        newdir = os.path.join(self.dir, "nested", "deep")
        report.ensure_reports_dir(newdir)
        self.assertTrue(os.path.isdir(newdir))

    def test_custom_filename(self):
        paths = report.generate_report({"a": 1}, filename="custom_report",
                                       path=self.dir)
        self.assertTrue(paths["json"].endswith("custom_report.json"))
        self.assertTrue(paths["markdown"].endswith("custom_report.md"))


if __name__ == "__main__":
    unittest.main()
