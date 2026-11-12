# Project Status — Purple Team Detection Validation Lab

## Estimated Progress

85%

## Completed Deliverables

- Repository structure and Git version control
- MITRE ATT&CK T1059.001 scenario
- Synthetic Sysmon Event ID 1 telemetry
- Synthetic PowerShell Event ID 4104 telemetry
- Baseline and contextual Sigma rules
- Python detection validator
- False positive and false negative evaluation
- Confusion matrix and performance metrics
- Sigma to Splunk SPL conversion
- Formal Sigma rule validation
- Synthetic telemetry generator
- Event correlation engine
- Integrated Markdown reporting
- Automated unit tests
- Full pipeline orchestration

## Current Validation

- 38 automated tests passed
- 2 Sigma rules validated
- 8 synthetic process events
- 2 synthetic Script Block events
- Baseline and contextual detection comparison
- Full pipeline execution successful

## Technologies

- Kali Linux
- Python
- MITRE ATT&CK
- Sigma
- pySigma
- Sigma CLI
- Splunk SPL
- Git

## Remaining Work

- Improve detection robustness
- Expand false positive and false negative scenarios
- Improve event correlation
- Finalize technical documentation
- Organize evidence and reports
- Prepare GitHub publication

## Limitations

All telemetry is synthetic.
No real Windows endpoint has been monitored.
No live Splunk execution has been performed.
No real Atomic Red Team execution has been performed.

## Objective

Demonstrate a reproducible Purple Team detection
validation workflow using threat-informed detection,
synthetic telemetry, Python automation and Sigma.
