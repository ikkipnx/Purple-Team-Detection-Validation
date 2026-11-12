# Scenario 01 — PowerShell Encoded Command

## Objective

Validate the detection of PowerShell execution using
the EncodedCommand parameter.

## MITRE ATT&CK

- Technique: T1059.001
- Name: PowerShell
- Tactic: Execution

## Test cases

### Test 01 — Suspicious behavior

PowerShell execution using the -EncodedCommand parameter.

Expected result: DETECTED

### Test 02 — Benign behavior

PowerShell execution using the Get-Process cmdlet.

Expected result: NOT DETECTED

## Data source

Synthetic Sysmon Event ID 1 (Process Creation).

## Important

The events used in this initial phase are synthetic fixtures.
They are not real telemetry collected from a Windows endpoint.
