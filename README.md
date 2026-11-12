# Purple Team Detection Validation Lab

A Python-based Purple Team laboratory focused on threat-informed
detection engineering, synthetic telemetry generation, event
correlation, Sigma rule validation and automated reporting.

## Project Overview

This project demonstrates a reproducible detection validation
workflow using MITRE ATT&CK, Sigma, Python and synthetic Windows
security telemetry.

The initial investigation focuses on PowerShell execution
(T1059.001), evaluating baseline and contextual detection rules.

## Objectives

- Translate ATT&CK techniques into detection hypotheses.
- Develop portable Sigma detection rules.
- Generate synthetic Sysmon and PowerShell telemetry.
- Evaluate true positives, false positives and false negatives.
- Correlate process creation and PowerShell Script Block events.
- Convert Sigma rules into Splunk SPL.
- Automate validation and technical reporting.

## Architecture

MITRE ATT&CK
     |
     v
Detection Engineering
     |
     v
Sigma Rules
     |
     v
Synthetic Telemetry Generator
     |
     v
Python Event Correlation
     |
     v
Detection Evaluation
     |
     v
Automated Purple Team Report

## Initial Detection Scenario

**MITRE ATT&CK:** T1059.001 — PowerShell

The laboratory evaluates encoded PowerShell command execution
across Windows PowerShell and PowerShell 7.

Two detection approaches are compared:

- Baseline detection: identifies encoded PowerShell execution.
- Contextual detection: applies a specific administrative
  context exclusion.

The evaluation demonstrates how an overly broad exclusion
can introduce false negatives.

## Technologies

| Technology | Purpose |
|---|---|
| Python | Detection logic, automation and correlation |
| MITRE ATT&CK | Adversary technique mapping |
| Sigma | Portable detection rules |
| pySigma | Rule validation and processing |
| Sigma CLI | Rule conversion |
| Splunk SPL | Detection query output |
| Sysmon format | Synthetic process telemetry |
| PowerShell | Synthetic Script Block telemetry |
| Git | Version control |

## Detection Evaluation

The current synthetic dataset contains eight process events.

| Metric | Baseline | Contextual |
|---|---:|---:|
| True Positives | 5 | 4 |
| True Negatives | 2 | 3 |
| False Positives | 1 | 0 |
| False Negatives | 0 | 1 |
| Accuracy | 87.5% | 87.5% |
| Precision | 83.3% | 100% |
| Recall | 100% | 80% |
| F1-score | 90.9% | 88.9% |

These results demonstrate the trade-off between reducing false
positives and preserving detection coverage.

They are specific to the synthetic evaluation dataset and
must not be interpreted as production detection performance.

## Event Correlation

The correlation engine uses:

- Sysmon Event ID 1 — Process Creation.
- PowerShell Event ID 4104 — Script Block Logging.
- Computer identity and Process ID for correlation.

The synthetic scenario produces:

- 8 process creation events.
- 2 Script Block events.
- 1 suspicious behavioral pattern.
- 1 process with no configured suspicious pattern.
- 6 processes without a matching Script Block event.

The behavioral classification is heuristic and does not
independently establish malicious activity.

## Project Structure

```text
Purple-Team-Detection-Validation/
├── data/
│   ├── fixtures/
│   ├── generated/
│   ├── processed/
│   └── raw/
├── detections/
│   └── sigma/
├── docs/
├── reports/
│   └── converted/
├── src/
├── tests/
├── .gitignore
└── README.md

```

## Installation

Create and activate a Python virtual environment:

`python3 -m venv .venv`

`source .venv/bin/activate`

Install Sigma CLI:

`python -m pip install sigma-cli==4.0.1`

Install the Splunk backend:

`sigma plugin install splunk`

## Run the Laboratory

Execute the complete pipeline:

`python3 src/run_lab.py`

The pipeline performs:

1. Sigma rule validation.
2. Detection evaluation.
3. Synthetic telemetry generation.
4. Event correlation.
5. Automated Markdown report generation.
6. Unit test execution.

## Run Tests Independently

`python3 -m unittest discover -s tests -v`

## Generated Reports

The main report is available at:

`reports/detection-validation-report.md`

Additional artifacts include:

- Baseline Splunk query.
- Contextual Splunk query.
- Event correlation results.
- Synthetic telemetry datasets.
- Project status documentation.

## Limitations

This repository currently uses synthetic telemetry.

- No real Windows endpoint has been monitored.
- No live Splunk search has been executed.
- No real Atomic Red Team execution has been performed.
- Detection metrics are based on a controlled synthetic dataset.
- Behavioral indicators require additional investigation.

Successful Sigma conversion does not prove runtime
execution in a live SIEM environment.

Atomic Red Team is a potential future extension of this lab.

## Author

Cybersecurity | Cyber Threat Intelligence | Detection Engineering | Purple Team
