# Purple Team Detection Validation Report

Report date: 2026-11-12

## 1. Objective

Evaluate PowerShell detection rules using synthetic telemetry, automated tests and event correlation.

## 2. Laboratory Environment

- MITRE ATT&CK: T1059.001
- Sysmon Event ID 1: Synthetic Process Creation
- PowerShell Event ID 4104: Synthetic Script Block Logging
- Detection: Sigma
- Conversion: Splunk SPL
- Analysis: Python

## 3. Detection Evaluation

| Metric | Baseline | Contextual |
|---|---:|---:|
| TP | 5 | 4 |
| TN | 2 | 3 |
| FP | 1 | 0 |
| FN | 0 | 1 |
| Accuracy | 87.5% | 87.5% |
| Precision | 83.3% | 100.0% |
| Recall | 100.0% | 80.0% |
| F1-score | 90.9% | 88.9% |

## 4. Synthetic Telemetry

- Process Creation events: 8
- Script Block events: 2

## 5. Event Correlation

| Correlation status | Quantity |
|---|---:|
| SUSPICIOUS_PATTERN | 1 |
| NO_CONFIGURED_PATTERN | 1 |
| NO_MATCHING_SCRIPTBLOCK | 6 |
| MISSING_CORRELATION_FIELDS | 0 |

## 6. Baseline Splunk Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (((Image IN ("*\\powershell.exe", "*\\pwsh.exe")) CommandLine="*-EncodedCommand*") OR (Image="*\\pwsh.exe" (CommandLine IN ("* -e *", "* -ec *"))))
```

## 7. Contextual Splunk Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (((Image IN ("*\\powershell.exe", "*\\pwsh.exe")) CommandLine="*-EncodedCommand*") OR (Image="*\\pwsh.exe" (CommandLine IN ("* -e *", "* -ec *")))) NOT (ParentImage="C:\\Program Files\\Company\\AutomationAgent.exe" User="LAB\\admin")
```

## 8. Technical Analysis

The baseline rule maintains full recall in the synthetic evaluation but generates one false positive.

The contextual rule reduces false positives but introduces one false negative in the synthetic evaluation.

Script Block correlation identifies one benign process and one process with a suspicious combination of indicators.

These indicators support investigation but do not prove malicious activity.

## 9. Limitations

- All events are synthetic.
- No real Windows endpoint was monitored.
- No live Splunk search was executed.
- Correlation uses Computer and ProcessId.
- PID reuse and event timing require additional handling.
- Correlation patterns are heuristic.

## 10. Recommendations

1. Expand benign and suspicious test scenarios.
2. Improve contextual filtering without losing recall.
3. Add timestamp-aware event correlation.
4. Validate rules against representative telemetry.
5. Preserve synthetic and real telemetry separately.

## 11. Conclusion

The laboratory integrates synthetic telemetry generation, detection evaluation, event correlation and automated reporting.

Results represent controlled laboratory tests and must not be interpreted as production performance.
