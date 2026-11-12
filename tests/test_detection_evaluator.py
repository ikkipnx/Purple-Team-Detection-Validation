import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from detection_evaluator import (
    DEFAULT_FIXTURE,
    DEFAULT_MANIFEST,
    evaluate,
)
from detection_validator import (
    detect_encoded_powershell,
    detect_encoded_powershell_tuned,
    load_events,
)


class TestDetectionEvaluator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = load_events(DEFAULT_FIXTURE)

    def test_baseline_confusion_matrix(self):
        metrics, _ = evaluate(
            self.events,
            DEFAULT_MANIFEST,
            detect_encoded_powershell,
        )

        self.assertEqual(metrics["TP"], 4)
        self.assertEqual(metrics["TN"], 2)
        self.assertEqual(metrics["FP"], 1)
        self.assertEqual(metrics["FN"], 0)

    def test_tuned_confusion_matrix(self):
        metrics, _ = evaluate(
            self.events,
            DEFAULT_MANIFEST,
            detect_encoded_powershell_tuned,
        )

        self.assertEqual(metrics["TP"], 4)
        self.assertEqual(metrics["TN"], 3)
        self.assertEqual(metrics["FP"], 0)
        self.assertEqual(metrics["FN"], 0)


if __name__ == "__main__":
    unittest.main()
