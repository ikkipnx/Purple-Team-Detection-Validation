import unittest

from src.synthetic_telemetry_generator import generate_telemetry

from src.event_correlator import (
    PROCESS_FIXTURE,
    SCRIPTBLOCK_FIXTURE,
    correlate_events,
    get_correlation_key,
    has_suspicious_script_pattern,
    load_jsonl,
)


class TestEventCorrelator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        generate_telemetry()

        cls.processes = load_jsonl(PROCESS_FIXTURE, 1)

        cls.scriptblocks = load_jsonl(
            SCRIPTBLOCK_FIXTURE,
            4104,
        )

        cls.results = correlate_events(
            cls.processes,
            cls.scriptblocks,
        )

    def test_eight_processes_loaded(self):
        self.assertEqual(len(self.processes), 8)

    def test_two_scriptblocks_loaded(self):
        self.assertEqual(len(self.scriptblocks), 2)

    def test_all_processes_have_correlation_keys(self):
        for event in self.processes:
            self.assertIsNotNone(get_correlation_key(event))

    def test_process_ids_are_unique(self):
        ids = [event["ProcessId"] for event in self.processes]

        self.assertEqual(len(ids), len(set(ids)))

    def test_benign_process_is_correlated(self):
        result = next(
            event for event in self.results
            if event["ProcessId"] == 7007
        )

        self.assertEqual(
            result["Status"],
            "NO_CONFIGURED_PATTERN",
        )

    def test_suspicious_process_is_correlated(self):
        result = next(
            event for event in self.results
            if event["ProcessId"] == 7008
        )

        self.assertEqual(
            result["Status"],
            "SUSPICIOUS_PATTERN",
        )

    def test_six_processes_have_no_scriptblock_match(self):
        unmatched = [
            event for event in self.results
            if event["Status"] == "NO_MATCHING_SCRIPTBLOCK"
        ]

        self.assertEqual(len(unmatched), 6)

    def test_different_computer_does_not_match(self):
        process = dict(self.processes[-1])
        process["Computer"] = "LAB-OTHER"

        results = correlate_events(
            [process],
            self.scriptblocks,
        )

        self.assertEqual(
            results[0]["Status"],
            "NO_MATCHING_SCRIPTBLOCK",
        )

    def test_missing_process_id_is_rejected(self):
        event = {"Computer": "LAB-WIN11"}

        self.assertIsNone(get_correlation_key(event))

    def test_network_indicator_alone_is_not_enough(self):
        script = (
            "Invoke-WebRequest "
            "-Uri https://example.invalid"
        )

        self.assertFalse(
            has_suspicious_script_pattern(script)
        )


if __name__ == "__main__":
    unittest.main()
