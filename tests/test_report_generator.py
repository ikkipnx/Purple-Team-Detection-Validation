import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from report_generator import generate_report


class TestReportGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.report_path = (
            Path(cls.temp_dir.name) / "integrated-report.md"
        )

        cls.result = generate_report(cls.report_path)

        cls.content = cls.report_path.read_text(
            encoding="utf-8"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_report_file_exists(self):
        self.assertTrue(self.report_path.exists())

    def test_report_includes_detection_metrics(self):
        self.assertIn("Detection Evaluation", self.content)

    def test_report_includes_correlation_results(self):
        self.assertIn("Event Correlation", self.content)

    def test_report_includes_suspicious_pattern(self):
        self.assertIn("SUSPICIOUS_PATTERN", self.content)

    def test_one_suspicious_pattern_is_reported(self):
        self.assertEqual(
            self.result["correlation"]["SUSPICIOUS_PATTERN"], 1
        )

    def test_six_unmatched_processes_are_reported(self):
        self.assertEqual(
            self.result["correlation"]["NO_MATCHING_SCRIPTBLOCK"], 6
        )


if __name__ == "__main__":
    unittest.main()
