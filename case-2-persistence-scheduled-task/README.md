# Case 02 — Persistence via Scheduled Task (Windows)

## Overview
This detection case documents the creation of a scheduled task on a Windows endpoint monitored by Wazuh.
Scheduled tasks are a **commonly abused persistence mechanism**, allowing attackers to execute commands on logon, startup, or at regular intervals.

This activity must be validated to distinguish between **legitimate administrative automation** and **malicious persistence**.

---

## Detection Goal
Detect and analyze:
- Creation of new scheduled tasks.
- Potential misuse of scheduled tasks as a persistence mechanism.

Determine whether the task creation is **authorized** or **malicious**.

---

## MITRE ATT&CK Mapping
- **T1053.005** – Scheduled Task / Job: Scheduled Task
- **TA0003** – Persistence

---

## Endpoint Information
- **Hostname:** WIN10-ENDPOINT
- **IP Address:** 192.168.56.103
- **Operating System:** Windows 10 Pro

---

## Attack Simulation (Lab)
The following activity was executed in a controlled lab environment:

1. A scheduled task was created on the Windows endpoint.
2. The task was configured to execute automatically.

This activity was performed for **educational and testing purposes only**.

---

## Detection
The following Windows Security Event was detected by Wazuh:

- **EventID 4698** — A scheduled task was created

---

## Queries Used
```
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4698
```

---

## Key Fields Observed
The following fields are critical for investigation:

- **SubjectUserName** – Account that created the task
- **TaskName**
- **TaskContent / Command**
- **RunAsUser**
- **ComputerName**
- **Timestamp**

These fields help determine **who created the task**, **what it executes**, and **under what context**.

---

## Analysis (SOC Triage)
Scheduled tasks are frequently abused by attackers to maintain persistence.

During triage, the following should be validated:
- Is the subject user part of IT or system administrators?
- Does the task name appear legitimate or suspicious?
- What command or script does the task execute?
- How often does the task run (trigger frequency)?
- Does the task execute at startup or user logon?
- Is this task present on other endpoints?
- Was the task created shortly after suspicious activity?

---

## Severity
**Medium**

### Severity Rationale
- Scheduled tasks can be legitimate administrative automation.
- Severity should be escalated to **High** if:
  - Created by non-IT accounts
  - Executes suspicious commands or scripts
  - Runs with elevated privileges
  - Persists across reboots or user logons

---

## False Positives & Tuning

### Potential False Positives
- IT automation tasks
- System maintenance or update tasks
- Backup or monitoring scripts

### Tuning Recommendations
- Allowlist known administrative task names and paths
- Alert when tasks execute binaries from user-writable directories
- Correlate with suspicious process execution or network activity
- Increase severity when combined with other persistence techniques

---

## Response & Remediation
Upon detection, the scheduled task was removed from the endpoint.

---

## Verification
Remediation was verified directly on the endpoint using the following command:

```
schtasks /query /tn "WinPersistTest"
```

The system returned that the task does not exist, confirming successful removal.

---

## Evidence
Screenshots of the detected event and remediation verification are included in this folder.

---

## Screenshots

### EventID 4698 — Scheduled Task Created
![EventID 4698](./evidence-4698.png)

### Remediation Verification — schtasks /query
![Verification](./verification-schtasks-query.png)

---

## Analyst Notes
Scheduled task creation is a **high-confidence persistence technique** when abused.
Context such as task name, execution command, and creator account is critical to accurately assess risk.
