import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_FIXTURE = (
    PROJECT_ROOT
    / "data"
    / "fixtures"
    / "sysmon-process-creation.jsonl"
)

AUTHORIZED_PARENT = (
    r"C:\Program Files\Company\AutomationAgent.exe"
).casefold()

AUTHORIZED_USER = "lab\\admin"


def detect_encoded_powershell(event):
    """Detecção original, sem exclusões contextuais."""

    if not isinstance(event, dict):
        return False

    if event.get("EventID") != 1:
        return False

    image = event.get("Image", "")
    command_line = event.get("CommandLine", "")

    if not isinstance(image, str):
        return False

    if not isinstance(command_line, str):
        return False

    executable = image.casefold().split("\\")[-1]
    arguments = command_line.casefold().split()

    if executable == "powershell.exe":
        return "-encodedcommand" in arguments

    if executable == "pwsh.exe":
        encoded_parameters = {
            "-encodedcommand",
            "-e",
            "-ec",
        }
        return any(
            arg.strip('"') in encoded_parameters
            for arg in arguments
        )

    return False


def detect_encoded_powershell_tuned(event):
    """Detecção contextual com exceção administrativa restrita."""

    if not detect_encoded_powershell(event):
        return False

    parent = event.get("ParentImage", "")
    user = event.get("User", "")

    # Sem contexto suficiente, mantemos a detecção.
    if not isinstance(parent, str) or not isinstance(user, str):
        return True

    authorized_context = (
        parent.casefold() == AUTHORIZED_PARENT
        and user.casefold() == AUTHORIZED_USER
    )

    return not authorized_context


def load_events(file_path):
    events = []

    with file_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Erro no JSON da linha {line_number}: {error}"
                )

            if not isinstance(event, dict):
                raise ValueError(
                    f"A linha {line_number} não contém um objeto JSON."
                )

            events.append(event)

    return events


def main():
    file_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else DEFAULT_FIXTURE
    )

    try:
        events = load_events(file_path)
    except (OSError, ValueError) as error:
        print(f"[ERRO] {error}")
        return 1

    detections = 0

    print("\n===== CONTEXTUAL DETECTION VALIDATOR =====\n")

    for index, event in enumerate(events, start=1):
        detected = detect_encoded_powershell_tuned(event)

        status = "DETECTED" if detected else "NOT DETECTED"

        if detected:
            detections += 1

        print(f"[{index:02}] {status}")
        print(f"     Executable: {event.get('Image', 'N/A')}")
        print(f"     User: {event.get('User', 'N/A')}")
        print()

    print("===== VALIDATION SUMMARY =====")
    print(f"Events processed: {len(events)}")
    print(f"Detections: {detections}")
    print(f"Not detected: {len(events) - detections}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
