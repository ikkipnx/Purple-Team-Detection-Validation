import csv
from pathlib import Path

from detection_validator import (
    DEFAULT_FIXTURE,
    detect_encoded_powershell,
    detect_encoded_powershell_tuned,
    load_events,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "data"
    / "fixtures"
    / "evaluation-manifest.csv"
)


def evaluate(events, manifest_path, detector=detect_encoded_powershell):

    with manifest_path.open(
        "r", encoding="utf-8", newline=""
    ) as file:
        rows = list(csv.DictReader(file))

    if len(rows) != len(events):
        raise ValueError(
            "Quantidade de casos diferente da quantidade de eventos."
        )

    metrics = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    results = []

    for row in rows:
        index = int(row["event_index"]) - 1

        if index < 0 or index >= len(events):
            raise ValueError("Índice de evento inválido.")

        expected = row["expected_alert"].strip().lower()

        if expected not in ("true", "false"):
            raise ValueError("expected_alert deve ser true ou false.")

        expected_alert = expected == "true"
        detected = detector(events[index])

        if expected_alert and detected:
            classification = "TP"
        elif not expected_alert and not detected:
            classification = "TN"
        elif not expected_alert and detected:
            classification = "FP"
        else:
            classification = "FN"

        metrics[classification] += 1

        results.append({
            "case_id": row["case_id"],
            "context": row["context"],
            "classification": classification,
        })

    total = len(events)
    tp, tn, fp, fn = (
        metrics["TP"], metrics["TN"],
        metrics["FP"], metrics["FN"]
    )

    metrics["accuracy"] = (tp + tn) / total if total else 0
    metrics["precision"] = tp / (tp + fp) if tp + fp else 0
    metrics["recall"] = tp / (tp + fn) if tp + fn else 0

    precision = metrics["precision"]
    recall = metrics["recall"]

    metrics["f1"] = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    return metrics, results


def print_report(title, metrics, results):

    print(f"\n===== {title} =====")

    for result in results:
        print(
            f"[{result['case_id']}] "
            f"{result['classification']} | "
            f"{result['context']}"
        )

    print("\nConfusion Matrix:")

    for key in ("TP", "TN", "FP", "FN"):
        print(f"{key}: {metrics[key]}")

    print("\nPerformance Metrics:")

    for key in ("accuracy", "precision", "recall", "f1"):
        print(f"{key.capitalize()}: {metrics[key]:.1%}")


def main():

    try:
        events = load_events(DEFAULT_FIXTURE)

        baseline, baseline_results = evaluate(
            events, DEFAULT_MANIFEST, detect_encoded_powershell
        )

        tuned, tuned_results = evaluate(
            events, DEFAULT_MANIFEST, detect_encoded_powershell_tuned
        )

    except (OSError, ValueError, KeyError) as error:
        print(f"[ERRO] {error}")
        return 1

    print_report("BASELINE DETECTION", baseline, baseline_results)
    print_report("CONTEXTUAL DETECTION", tuned, tuned_results)

    print("\nNote: Synthetic laboratory evaluation only.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
