# Purple Team Detection Validation Report

Report date: 2026-11-12

## 1. Objective

Evaluate and compare two Sigma detection rule versions for encoded PowerShell execution.

## 2. Test Environment

- Data source: Synthetic Sysmon Event ID 1 fixtures
- Detection format: Sigma
- Conversion target: Splunk SPL
- Evaluation engine: Custom Python validator
- Events evaluated: 7

## 3. Detection Comparison

| Metric | Baseline | Contextual |
|---|---:|---:|
| TP | 4 | 4 |
| TN | 2 | 3 |
| FP | 1 | 0 |
| FN | 0 | 0 |
| Accuracy | 85.7% | 100.0% |
| Precision | 80.0% | 100.0% |
| Recall | 100.0% | 100.0% |
| F1-score | 88.9% | 100.0% |

## 4. Analysis

The baseline rule identified all four positive test cases but generated one false positive.

The contextual version excluded the specifically defined synthetic administrative automation context while preserving the four positive detections.

This result demonstrates the potential benefit of contextual filtering in detection engineering.

## 5. Baseline Splunk Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (((Image IN ("*\\powershell.exe", "*\\pwsh.exe")) CommandLine="*-EncodedCommand*") OR (Image="*\\pwsh.exe" (CommandLine IN ("* -e *", "* -ec *"))))
```

## 6. Contextual Splunk Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (((Image IN ("*\\powershell.exe", "*\\pwsh.exe")) CommandLine="*-EncodedCommand*") OR (Image="*\\pwsh.exe" (CommandLine IN ("* -e *", "* -ec *")))) NOT (ParentImage="C:\\Program Files\\Company\\AutomationAgent.exe" User="LAB\\admin")
```

## 7. Limitations

- All evaluation events are synthetic.
- No live Splunk execution has been performed.
- No real Windows Sysmon telemetry has been collected.
- The contextual exclusion is based on a synthetic user and parent process combination.
- Production allowlisting requires independent verification of process identity, integrity and authorization.

## 8. Recommendations

1. Validate the rules against real Sysmon telemetry.
2. Test additional PowerShell execution patterns.
3. Assess process parent identity and digital signatures.
4. Reevaluate false positives using representative organizational activity.
5. Perform runtime validation in a SIEM environment.

## 9. Conclusion

Both Sigma rules were successfully converted to Splunk SPL. The contextual version improved the results within the synthetic test dataset.

These metrics must not be interpreted as production detection performance.
