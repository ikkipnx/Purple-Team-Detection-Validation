import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

STEPS = [
    (
        "Sigma Rule Validation",
        [sys.executable, "src/sigma_rule_validator.py"],
    ),
    (
        "Detection Evaluation",
        [sys.executable, "src/detection_evaluator.py"],
    ),
    (
        "Integrated Report and Telemetry",
        [sys.executable, "src/report_generator.py"],
    ),
    (
        "Automated Test Suite",
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-v",
        ],
    ),
]


def main():
    print("\n========================================")
    print(" PURPLE TEAM DETECTION VALIDATION LAB")
    print(" FULL PIPELINE EXECUTION")
    print("========================================")

    for number, (name, command) in enumerate(STEPS, start=1):

        print(f"\n[{number}/{len(STEPS)}] {name}")
        print("-" * 45)

        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            check=False,
        )

        if result.returncode != 0:
            print(f"\n[FAILED] {name}")
            print("Pipeline execution interrupted.")
            return result.returncode

        print(f"\n[OK] {name}")

    print("\n========================================")
    print(" ALL PIPELINE STAGES COMPLETED")
    print("========================================")

    print("\nGenerated report:")
    print("reports/detection-validation-report.md")

    print("\nPipeline completed successfully!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
