import unittest

from src.sigma_rule_validator import (
    RULE_FILES,
    validate_rules,
)


class TestSigmaRuleValidator(unittest.TestCase):

    def test_two_sigma_rules_exist(self):
        self.assertEqual(len(RULE_FILES), 2)

    def test_no_high_severity_issues(self):
        issues = validate_rules()

        high_issues = [
            issue for issue in issues
            if issue.severity.name == "HIGH"
        ]

        self.assertEqual(high_issues, [])


if __name__ == "__main__":
    unittest.main()
