import json
import tempfile
import unittest
from pathlib import Path

from src.synthetic_telemetry_generator import generate_telemetry


class TestSyntheticTelemetryGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.output_dir = Path(cls.temp_dir.name)

        cls.processes, cls.scriptblocks = generate_telemetry(
            cls.output_dir
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_eight_process_events_generated(self):
        self.assertEqual(len(self.processes), 8)

    def test_all_processes_have_correlation_fields(self):
        required = (
            "EventID",
            "ProcessId",
            "Computer",
            "UtcTime",
            "ParentProcessId",
        )

        for event in self.processes:
            for field in required:
                self.assertIn(field, event)

    def test_process_ids_are_unique(self):
        ids = [event["ProcessId"] for event in self.processes]
        self.assertEqual(len(ids), len(set(ids)))

    def test_two_scriptblock_events_generated(self):
        self.assertEqual(len(self.scriptblocks), 2)

    def test_scriptblocks_match_existing_processes(self):
        process_keys = {
            (e["Computer"].casefold(), str(e["ProcessId"]))
            for e in self.processes
        }

        for event in self.scriptblocks:
            key = (
                event["Computer"].casefold(),
                str(event["ProcessId"]),
            )
            self.assertIn(key, process_keys)

    def test_jsonl_files_are_valid(self):
        for filename in (
            "sysmon-process-creation.jsonl",
            "powershell-scriptblock-events.jsonl",
        ):
            path = self.output_dir / filename

            with path.open(encoding="utf-8") as file:
                for line in file:
                    self.assertIsInstance(json.loads(line), dict)


if __name__ == "__main__":
    unittest.main()
