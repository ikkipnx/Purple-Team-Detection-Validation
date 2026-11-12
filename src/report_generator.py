from datetime import date
from pathlib import Path

from detection_evaluator import (
    DEFAULT_MANIFEST,
    evaluate,
)
from detection_validator import (
    DEFAULT_FIXTURE,
    detect_encoded_powershell,
    detect_encoded_powershell_tuned,
    load_events,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

REPORT_PATH = (
    PROJECT_ROOT
    / "reports"
    / "detection-validation-report.md"
)

BASELINE_SPL = (
    PROJECT_ROOT
    / "reports"
    / "converted"
    / "powershell_baseline.spl"
)

CONTEXTUAL_SPL = (
    PROJECT_ROOT
    / "reports"
    / "converted"
    / "powershell_contextual.spl"
)


def percentage(value):
    return f"{value:.1%}"


def main():

    # Carregar eventos sintéticos
    events = load_events(DEFAULT_FIXTURE)

    # Avaliar as duas versões
    baseline, _ = evaluate(
        events,
        DEFAULT_MANIFEST,
        detect_encoded_powershell,
    )

    contextual, _ = evaluate(
        events,
        DEFAULT_MANIFEST,
        detect_encoded_powershell_tuned,
    )

    # Carregar consultas SPL
    baseline_spl = BASELINE_SPL.read_text(encoding="utf-8").strip()
    contextual_spl = CONTEXTUAL_SPL.read_text(
        encoding="utf-8"
    ).strip()

    # Construir o relatório
    lines = [
        "# Purple Team Detection Validation Report",
        "",
        f"Report date: {date.today().isoformat()}",
        "",
        "## 1. Objective",
        "",
        "Evaluate and compare two Sigma detection rule versions "
        "for encoded PowerShell execution.",
        "",
        "## 2. Test Environment",
        "",
        "- Data source: Synthetic Sysmon Event ID 1 fixtures",
        "- Detection format: Sigma",
        "- Conversion target: Splunk SPL",
        "- Evaluation engine: Custom Python validator",
        f"- Events evaluated: {len(events)}",
        "",
        "## 3. Detection Comparison",
        "",
        "| Metric | Baseline | Contextual |",
        "|---|---:|---:|",
        f"| TP | {baseline['TP']} | {contextual['TP']} |",
        f"| TN | {baseline['TN']} | {contextual['TN']} |",
        f"| FP | {baseline['FP']} | {contextual['FP']} |",
        f"| FN | {baseline['FN']} | {contextual['FN']} |",
        f"| Accuracy | {percentage(baseline['accuracy'])} | "
        f"{percentage(contextual['accuracy'])} |",
        f"| Precision | {percentage(baseline['precision'])} | "
        f"{percentage(contextual['precision'])} |",
        f"| Recall | {percentage(baseline['recall'])} | "
        f"{percentage(contextual['recall'])} |",
        f"| F1-score | {percentage(baseline['f1'])} | "
        f"{percentage(contextual['f1'])} |",
        "",
        "## 4. Analysis",
        "",
        "The baseline rule identified all four positive test cases "
        "but generated one false positive.",
        "",
        "The contextual version excluded the specifically defined "
        "synthetic administrative automation context while preserving "
        "the four positive detections.",
        "",
        "This result demonstrates the potential benefit of contextual "
        "filtering in detection engineering.",
        "",
        "## 5. Baseline Splunk Query",
        "",
        "```spl",
        baseline_spl,
        "```",
        "",
        "## 6. Contextual Splunk Query",
        "",
        "```spl",
        contextual_spl,
        "```",
        "",
        "## 7. Limitations",
        "",
        "- All evaluation events are synthetic.",
        "- No live Splunk execution has been performed.",
        "- No real Windows Sysmon telemetry has been collected.",
        "- The contextual exclusion is based on a synthetic "
        "user and parent process combination.",
        "- Production allowlisting requires independent verification "
        "of process identity, integrity and authorization.",
        "",
        "## 8. Recommendations",
        "",
        "1. Validate the rules against real Sysmon telemetry.",
        "2. Test additional PowerShell execution patterns.",
        "3. Assess process parent identity and digital signatures.",
        "4. Reevaluate false positives using representative "
        "organizational activity.",
        "5. Perform runtime validation in a SIEM environment.",
        "",
        "## 9. Conclusion",
        "",
        "Both Sigma rules were successfully converted to Splunk SPL. "
        "The contextual version improved the results within the "
        "synthetic test dataset.",
        "",
        "These metrics must not be interpreted as production "
        "detection performance.",
    ]

    REPORT_PATH.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print("===== REPORT GENERATOR =====")
    print(f"Report created: {REPORT_PATH}")
    print(f"Events evaluated: {len(events)}")
    print(
        f"Baseline false positives: {baseline['FP']}"
    )
    print(
        f"Contextual false positives: {contextual['FP']}"
    )
    print("\nReport generation completed successfully!")


if __name__ == "__main__":
    main()
