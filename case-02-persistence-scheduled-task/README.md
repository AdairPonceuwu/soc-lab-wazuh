# Case 02 — Persistence via Scheduled Task

## Summary
A scheduled task was created on a Windows endpoint as a persistence mechanism.

## Endpoint
- Hostname: WIN10-ENDPOINT
- IP: 192.168.56.103

## Detection
- EventID 4698 — Scheduled task created
- Source: Windows Security Log

## Query
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4698

## Analysis
Scheduled tasks are commonly abused by attackers to maintain persistence.
This activity maps to MITRE ATT&CK technique T1053.

## Response
The scheduled task was removed after detection.

## Verification
Remediation was verified using:
`schtasks /query /tn "WinPersistTest"`

The system returned:
"The system cannot find the file specified"

## MITRE ATT&CK
- T1053 — Scheduled Task / Job

## Severity
Medium
