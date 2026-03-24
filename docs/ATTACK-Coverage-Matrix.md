# MITRE ATT&CK Coverage Matrix

This matrix summarizes the current MITRE ATT&CK coverage of the lab based on **native Windows Security Event Logs** collected by **Wazuh**.

It is intended to show:

- which ATT&CK techniques are currently covered
- which Windows events support each detection case
- the current severity assigned to each scenario
- where future detection expansion is needed

---

## Current Coverage

| Case | Detection Focus | Tactic | Technique | ID | Event IDs | Log Source | Severity |
|------|------------------|--------|-----------|----|-----------|------------|----------|
| 01 | Local user creation + admin group membership | Persistence / Privilege Escalation | Create Account: Local Account / Account Manipulation | T1136.001 / T1098 | 4720, 4732 | Windows Security Event Log | Medium |
| 02 | Scheduled task persistence | Persistence | Scheduled Task / Job: Scheduled Task | T1053.005 | 4698 | Windows Security Event Log | Medium |
| 03 | Multiple failed logons followed by successful authentication | Credential Access / Initial Access | Brute Force | T1110 | 4625, 4624 | Windows Security Event Log | High |
| 04 | Suspicious PowerShell execution with bypass flags | Execution | PowerShell | T1059.001 | 4688 | Windows Security Event Log | High |

---

## Notes

This matrix reflects the current detection scope of the lab using only **native Windows Security telemetry**.

At this stage, the project focuses on high-value Windows use cases that can be validated without Sysmon or a commercial EDR.  
The goal is to demonstrate practical SOC analyst workflows, detection engineering logic, and MITRE ATT&CK alignment using the telemetry that is realistically available in a constrained lab environment.

---

## Coverage Highlights

The current lab provides visibility into four high-value detection areas:

- **Account creation and privilege assignment**
- **Persistence through scheduled tasks**
- **Credential attack patterns**
- **Suspicious PowerShell execution**

Together, these cases cover activity related to:

- persistence
- privilege escalation
- credential access
- initial access
- execution

---

## Current Limitations

The current ATT&CK coverage is intentionally scoped and does not yet include:

- remote administration abuse
- service creation or service abuse
- RDP-specific detections
- lateral movement patterns
- Linux telemetry
- Sysmon-based process enrichment
- broader multi-host correlation

These gaps are expected and will be addressed as the lab expands.

---

## Planned Coverage Expansion

Future improvements may include:

- correlation-based detections across multiple event types
- additional authentication abuse scenarios
- remote access detections
- local account abuse followed by successful logon correlation
- suspicious service creation
- Linux endpoint telemetry
- Sysmon-based comparisons for deeper process visibility

---

## Suggested Next Detection Cases

The following cases would strengthen ATT&CK coverage in future versions of the lab:

1. **New Local Admin Account → Successful Logon**
   - Extends account manipulation into authentication-based correlation

2. **Suspicious RDP Logon**
   - Adds remote access visibility and stronger logon-type analysis

3. **Service Creation for Persistence**
   - Expands Windows persistence coverage beyond scheduled tasks

4. **PowerShell + Network Activity Correlation**
   - Improves confidence for suspicious PowerShell execution

---

## Purpose of This Matrix

This matrix is included to make the project easier to review from a SOC, blue team, or recruiter perspective.

It helps show that the lab is not only a set of isolated screenshots or detections, but a structured effort to:

- map behavior to ATT&CK
- build reusable detection logic
- understand the limits of available telemetry
- identify realistic next steps for defensive coverage
