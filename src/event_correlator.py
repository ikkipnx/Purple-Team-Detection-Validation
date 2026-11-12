import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PROCESS_FIXTURE = (
    PROJECT_ROOT
    / "data"
    / "generated"
    / "sysmon-process-creation.jsonl"
)

SCRIPTBLOCK_FIXTURE = (
    PROJECT_ROOT
    / "data"
    / "generated"
    / "powershell-scriptblock-events.jsonl"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "powershell-correlation-results.json"
)


def load_jsonl(file_path, expected_event_id):
    events = []

    with file_path.open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"JSON inválido na linha {line_number}: {error}"
                )

            if not isinstance(event, dict):
                raise ValueError(
                    f"Evento inválido na linha {line_number}."
                )

            if event.get("EventID") != expected_event_id:
                raise ValueError(
                    f"EventID inesperado na linha {line_number}."
                )

            events.append(event)

    return events


def get_correlation_key(event):
    computer = event.get("Computer")
    process_id = event.get("ProcessId")

    if computer is None or process_id is None:
        return None

    return (
        str(computer).casefold(),
        str(process_id),
    )


def has_suspicious_script_pattern(script_text):

    if not isinstance(script_text, str):
        return False

    script = script_text.casefold()

    network_indicators = (
        "invoke-webrequest",
        "downloadstring",
        "start-bitstransfer",
    )

    execution_indicators = (
        "invoke-expression",
        "iex ",
        "[scriptblock]::create",
    )

    has_network = any(
        indicator in script
        for indicator in network_indicators
    )

    has_dynamic_execution = any(
        indicator in script
        for indicator in execution_indicators
    )

    return has_network and has_dynamic_execution


def correlate_events(process_events, scriptblock_events):

    scriptblock_index = {}

    for event in scriptblock_events:
        key = get_correlation_key(event)

        if key is None:
            continue

        scriptblock_index.setdefault(key, []).append(event)

    results = []

    for process in process_events:

        key = get_correlation_key(process)

        if key is None:
            status = "MISSING_CORRELATION_FIELDS"
            matches = []

        else:
            matches = scriptblock_index.get(key, [])

            if not matches:
                status = "NO_MATCHING_SCRIPTBLOCK"

            else:
                script_texts = [
                    event.get("ScriptBlockText", "")
                    for event in matches
                ]

                suspicious = any(
                    has_suspicious_script_pattern(script)
                    for script in script_texts
                )

                status = (
                    "SUSPICIOUS_PATTERN"
                    if suspicious
                    else "NO_CONFIGURED_PATTERN"
                )

        results.append({
            "ProcessId": process.get("ProcessId"),
            "Computer": process.get("Computer"),
            "User": process.get("User"),
            "Image": process.get("Image"),
            "Status": status,
            "MatchingEvents": len(matches),
            "ScriptBlockIds": [
                event.get("ScriptBlockId")
                for event in matches
            ],
        })

    return results


def main():

    try:
        processes = load_jsonl(PROCESS_FIXTURE, 1)

        scriptblocks = load_jsonl(
            SCRIPTBLOCK_FIXTURE,
            4104,
        )

        results = correlate_events(
            processes,
            scriptblocks,
        )

    except (OSError, ValueError) as error:
        print(f"[ERRO] {error}")
        return 1

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_FILE.write_text(
        json.dumps(results, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    suspicious = sum(
        event["Status"] == "SUSPICIOUS_PATTERN"
        for event in results
    )

    benign = sum(
        event["Status"] == "NO_CONFIGURED_PATTERN"
        for event in results
    )

    unmatched = sum(
        event["Status"] == "NO_MATCHING_SCRIPTBLOCK"
        for event in results
    )

    missing = sum(
        event["Status"] == "MISSING_CORRELATION_FIELDS"
        for event in results
    )

    print("\n===== PURPLE TEAM EVENT CORRELATOR =====\n")

    for event in results:
        print(
            f"PID: {event['ProcessId']} | "
            f"Computer: {event['Computer']} | "
            f"Status: {event['Status']}"
        )

    print("\n===== CORRELATION SUMMARY =====")
    print(f"Process events: {len(processes)}")
    print(f"Script Block events: {len(scriptblocks)}")
    print(f"Suspicious patterns: {suspicious}")
    print(f"No configured pattern: {benign}")
    print(f"No Script Block match: {unmatched}")
    print(f"Missing correlation fields: {missing}")

    print(f"\nOutput: {OUTPUT_FILE}")
    print("\nCorrelation completed!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
