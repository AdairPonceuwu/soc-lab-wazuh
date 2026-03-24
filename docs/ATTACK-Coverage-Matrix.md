# MITRE ATT&CK Coverage Matrix

| Case | Detection Focus | Tactic | Technique | ID | Event IDs | Log Source | Severity |
|------|------------------|--------|-----------|----|-----------|------------|----------|
| 01 | Local user creation + admin group membership | Persistence / Privilege Escalation | Create Account: Local Account / Account Manipulation | T1136.001 / T1098 | 4720, 4732 | Windows Security Event Log | Medium |
| 02 | Scheduled task persistence | Persistence | Scheduled Task / Job: Scheduled Task | T1053.005 | 4698 | Windows Security Event Log | Medium |
| 03 | Multiple failed logons followed by successful authentication | Credential Access / Initial Access | Brute Force | T1110 | 4625, 4624 | Windows Security Event Log | High |
| 04 | Suspicious PowerShell execution with bypass flags | Execution | PowerShell | T1059.001 | 4688 | Windows Security Event Log | High |

## Notes

This matrix summarizes the current ATT&CK coverage of the lab based on native Windows Security Event Logs collected by Wazuh.

It is intended to show:
- which techniques are currently covered
- which Windows events support each detection
- where future coverage expansion is needed

## Planned Coverage Expansion

Future improvements may include:
- correlation-based detections
- additional authentication abuse scenarios
- remote access detections
- Linux telemetry coverage
- Sysmon-based comparisons
