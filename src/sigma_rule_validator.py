from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RULES_DIR = PROJECT_ROOT / "detections" / "sigma"

RULE_FILES = sorted(RULES_DIR.glob("*.yml"))


def validate_rules():
    """Valida as regras utilizando os validadores oficiais do pySigma."""

    if not RULE_FILES:
        raise ValueError("Nenhuma regra YAML encontrada.")

    collection = SigmaCollection.load_ruleset([RULES_DIR])

    available_validators = (
        core_validators.values()
        if isinstance(core_validators, dict)
        else core_validators
    )

    validator = SigmaValidator(
        validators=available_validators
    )

    return validator.validate_rules(collection)


def main():

    try:
        issues = validate_rules()

    except Exception as error:
        print(f"[ERRO] Validação Sigma: {error}")
        return 1

    print("\n===== SIGMA RULE VALIDATION =====\n")

    print(f"Rules discovered: {len(RULE_FILES)}")

    for rule in RULE_FILES:
        print(f"[RULE] {rule.name}")

    print("\n===== VALIDATION FINDINGS =====")

    if not issues:
        print("No validation issues detected.")

    for issue in issues:
        print(f"[{issue.severity.name}] {issue}")

    high = sum(
        issue.severity.name == "HIGH"
        for issue in issues
    )

    medium = sum(
        issue.severity.name == "MEDIUM"
        for issue in issues
    )

    low = sum(
        issue.severity.name == "LOW"
        for issue in issues
    )

    print("\n===== SUMMARY =====")
    print(f"High: {high}")
    print(f"Medium: {medium}")
    print(f"Low: {low}")

    print("\nValidation completed.")

    return 1 if high else 0


if __name__ == "__main__":
    raise SystemExit(main())
