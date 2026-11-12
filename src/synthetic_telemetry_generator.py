import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SOURCE_PROCESS = (
    PROJECT_ROOT / "data/fixtures/sysmon-process-creation.jsonl"
)

SOURCE_SCRIPTBLOCK = (
    PROJECT_ROOT / "data/fixtures/powershell-scriptblock-events.jsonl"
)

OUTPUT_DIR = PROJECT_ROOT / "data/generated"

BASE_TIME = datetime(
    2026, 11, 12, 21, 0, 0, tzinfo=timezone.utc
)


def read_jsonl(path):
    events = []

    with path.open(encoding="utf-8") as file:
        for number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"JSON inválido em {path}, linha {number}: {error}"
                )

            if not isinstance(event, dict):
                raise ValueError(
                    f"Evento inválido em {path}, linha {number}."
                )

            events.append(event)

    return events


def write_jsonl(path, events):
    with path.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(
                json.dumps(event, ensure_ascii=False) + "\n"
            )


def generate_telemetry(output_dir=OUTPUT_DIR):
    """Gera telemetria sintética enriquecida e reproduzível."""

    processes = read_jsonl(SOURCE_PROCESS)
    scriptblocks = read_jsonl(SOURCE_SCRIPTBLOCK)

    if not processes:
        raise ValueError("Nenhum evento de processo encontrado.")

    enriched_processes = []

    for index, original in enumerate(processes, start=1):
        event = dict(original)

        if event.get("EventID") != 1:
            raise ValueError("Evento de processo com EventID inesperado.")

        process_id = event.setdefault("ProcessId", 7000 + index)

        event.setdefault("Computer", "LAB-WIN11")

        event.setdefault(
            "UtcTime",
            (BASE_TIME + timedelta(seconds=index)).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3],
        )

        is_automation = process_id in (7007, 7008)

        event.setdefault(
            "ParentProcessId",
            6500 if is_automation else 4000,
        )

        event.setdefault(
            "ParentImage",
            (
                r"C:\Program Files\Company\AutomationAgent.exe"
                if is_automation
                else r"C:\Windows\System32\cmd.exe"
            ),
        )

        enriched_processes.append(event)

    process_keys = {
        (
            event["Computer"].casefold(),
            str(event["ProcessId"]),
        )
        for event in enriched_processes
    }

    enriched_scriptblocks = []

    for event in scriptblocks:
        event = dict(event)

        if event.get("EventID") != 4104:
            raise ValueError("Evento Script Block com EventID inesperado.")

        computer = event.get("Computer")
        process_id = event.get("ProcessId")

        if computer is None or process_id is None:
            raise ValueError("Evento 4104 sem dados de correlação.")

        key = (computer.casefold(), str(process_id))

        if key not in process_keys:
            raise ValueError(
                f"Evento 4104 sem processo correspondente: {key}"
            )

        enriched_scriptblocks.append(event)

    output_dir.mkdir(parents=True, exist_ok=True)

    write_jsonl(
        output_dir / "sysmon-process-creation.jsonl",
        enriched_processes,
    )

    write_jsonl(
        output_dir / "powershell-scriptblock-events.jsonl",
        enriched_scriptblocks,
    )

    readme = """# Generated Synthetic Telemetry

These files are generated laboratory fixtures.

They do not originate from a real Windows endpoint.

- Sysmon Event ID 1: process creation
- PowerShell Event ID 4104: script block logging

All process identifiers, timestamps and hostnames are synthetic.
"""

    (output_dir / "README.md").write_text(
        readme,
        encoding="utf-8",
    )

    return enriched_processes, enriched_scriptblocks


def main():
    try:
        processes, scriptblocks = generate_telemetry()

    except (OSError, ValueError) as error:
        print(f"[ERRO] {error}")
        return 1

    missing_metadata = sum(
        not all(
            field in event
            for field in (
                "ProcessId",
                "Computer",
                "UtcTime",
                "ParentProcessId",
            )
        )
        for event in processes
    )

    print("\n===== SYNTHETIC TELEMETRY GENERATOR =====")
    print(f"Sysmon Event ID 1: {len(processes)}")
    print(f"PowerShell Event ID 4104: {len(scriptblocks)}")
    print(f"Processes missing metadata: {missing_metadata}")
    print(f"Output directory: {OUTPUT_DIR}")
    print("\nGeneration completed successfully!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
