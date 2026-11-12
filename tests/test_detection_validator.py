import unittest

from src.detection_validator import (
    DEFAULT_FIXTURE,
    detect_encoded_powershell,
    detect_encoded_powershell_tuned,
    load_events,
)


class TestDetectionValidator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = load_events(DEFAULT_FIXTURE)

    def test_fixture_has_seven_events(self):
        self.assertEqual(len(self.events), 7)

    def test_windows_powershell_encoded(self):
        self.assertTrue(detect_encoded_powershell(self.events[0]))

    def test_benign_windows_powershell(self):
        self.assertFalse(detect_encoded_powershell(self.events[1]))

    def test_pwsh_full_parameter(self):
        self.assertTrue(detect_encoded_powershell(self.events[2]))

    def test_pwsh_short_parameter_e(self):
        self.assertTrue(detect_encoded_powershell(self.events[3]))

    def test_pwsh_short_parameter_ec(self):
        self.assertTrue(detect_encoded_powershell(self.events[4]))

    def test_execution_policy_is_not_detected(self):
        self.assertFalse(detect_encoded_powershell(self.events[5]))

    def test_other_event_id(self):
        event = {
            "EventID": 3,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand ABC"
        }
        self.assertFalse(detect_encoded_powershell(event))

    def test_other_executable(self):
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe -EncodedCommand ABC"
        }
        self.assertFalse(detect_encoded_powershell(event))

    def test_approved_automation_is_suppressed(self):
        self.assertFalse(
            detect_encoded_powershell_tuned(self.events[6])
        )

    def test_different_parent_is_still_detected(self):
        event = dict(self.events[6])
        event["ParentImage"] = "C:\\Windows\\System32\\cmd.exe"

        self.assertTrue(
            detect_encoded_powershell_tuned(event)
        )


if __name__ == "__main__":
    unittest.main()
