import json
import sys
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

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

from synthetic_telemetry_generator import generate_telemetry

from event_correlator import (
    OUTPUT_FILE as CORRELATION_OUTPUT,
    correlate_events,
)


REPORT_PATH = (
    PROJECT_ROOT / "reports" / "detection-validation-report.md"
)

BASELINE_SPL = (
    PROJECT_ROOT / "reports/converted/powershell_baseline.spl"
)

CONTEXTUAL_SPL = (
    PROJECT_ROOT / "reports/converted/powershell_contextual.spl"
)


def percentage(value):
    return f"{value:.1%}"


def generate_report(report_path=REPORT_PATH):
    """Gera um relatório integrado de detecção e correlação."""

    processes, scriptblocks = generate_telemetry()

    correlation_results = correlate_events(
        processes,
        scriptblocks,
    )

    CORRELATION_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    CORRELATION_OUTPUT.write_text(
        json.dumps(
            correlation_results,
            indent=4,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    events = load_events(DEFAULT_FIXTURE)

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

    statuses = [
        "SUSPICIOUS_PATTERN",
        "NO_CONFIGURED_PATTERN",
        "NO_MATCHING_SCRIPTBLOCK",
        "MISSING_CORRELATION_FIELDS",
    ]

    summary = {
        status: sum(
            event["Status"] == status
            for event in correlation_results
        )
        for status in statuses
    }

    baseline_spl = BASELINE_SPL.read_text(
        encoding="utf-8"
    ).strip()

    contextual_spl = CONTEXTUAL_SPL.read_text(
        encoding="utf-8"
    ).strip()

    lines = [
        "# Purple Team Detection Validation Report",
        "",
        f"Report date: {date.today().isoformat()}",
        "",
        "## 1. Objective",
        "",
        "Evaluate PowerShell detection rules using synthetic telemetry, "
        "automated tests and event correlation.",
        "",
        "## 2. Laboratory Environment",
        "",
        "- MITRE ATT&CK: T1059.001",
        "- Sysmon Event ID 1: Synthetic Process Creation",
        "- PowerShell Event ID 4104: Synthetic Script Block Logging",
        "- Detection: Sigma",
        "- Conversion: Splunk SPL",
        "- Analysis: Python",
        "",
        "## 3. Detection Evaluation",
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
        "## 4. Synthetic Telemetry",
        "",
        f"- Process Creation events: {len(processes)}",
        f"- Script Block events: {len(scriptblocks)}",
        "",
        "## 5. Event Correlation",
        "",
        "| Correlation status | Quantity |",
        "|---|---:|",
    ]

    for status, quantity in summary.items():
        lines.append(f"| {status} | {quantity} |")

    lines.extend([
        "",
        "## 6. Baseline Splunk Query",
        "",
        "```spl",
        baseline_spl,
        "```",
        "",
        "## 7. Contextual Splunk Query",
        "",
        "```spl",
        contextual_spl,
        "```",
        "",
        "## 8. Technical Analysis",
        "",
        "The baseline rule maintains full recall in the synthetic "
        "evaluation but generates one false positive.",
        "",
        "The contextual rule reduces false positives but introduces "
        "one false negative in the synthetic evaluation.",
        "",
        "Script Block correlation identifies one benign process "
        "and one process with a suspicious combination of indicators.",
        "",
        "These indicators support investigation but do not prove "
        "malicious activity.",
        "",
        "## 9. Limitations",
        "",
        "- All events are synthetic.",
        "- No real Windows endpoint was monitored.",
        "- No live Splunk search was executed.",
        "- Correlation uses Computer and ProcessId.",
        "- PID reuse and event timing require additional handling.",
        "- Correlation patterns are heuristic.",
        "",
        "## 10. Recommendations",
        "",
        "1. Expand benign and suspicious test scenarios.",
        "2. Improve contextual filtering without losing recall.",
        "3. Add timestamp-aware event correlation.",
        "4. Validate rules against representative telemetry.",
        "5. Preserve synthetic and real telemetry separately.",
        "",
        "## 11. Conclusion",
        "",
        "The laboratory integrates synthetic telemetry generation, "
        "detection evaluation, event correlation and automated reporting.",
        "",
        "Results represent controlled laboratory tests and must not "
        "be interpreted as production performance.",
    ])

    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    report_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return {
        "baseline": baseline,
        "contextual": contextual,
        "correlation": summary,
        "report_path": report_path,
    }


def main():
    try:
        result = generate_report()
    except (OSError, ValueError, KeyError) as error:
        print(f"[ERRO] Report generation: {error}")
        return 1

    print("\n===== PURPLE TEAM REPORT GENERATOR =====")
    print("Processes generated: 8")
    print("Script Block events: 2")
    print(
        f"Suspicious patterns: "
        f"{result['correlation']['SUSPICIOUS_PATTERN']}"
    )
    print(
        f"Baseline false positives: "
        f"{result['baseline']['FP']}"
    )
    print(
        f"Contextual false negatives: "
        f"{result['contextual']['FN']}"
    )
    print(f"Report: {result['report_path']}")
    print("\nReport generation completed successfully!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
