# Sigma to Splunk Conversion Review

## Objective

Validate the conversion of Sigma detection rules into Splunk SPL.

## Backend

- Target: Splunk
- Processing pipeline: splunk_windows
- Tool: Sigma CLI
- Library: pySigma

## Converted rules

- Baseline: powershell_baseline.spl
- Contextual: powershell_contextual.spl

## Validation

Both rules were successfully parsed and converted.

## Limitation

Successful conversion does not prove execution in a live Splunk environment.
Runtime validation remains pending.

## Data classification

The validation uses synthetic laboratory events.
