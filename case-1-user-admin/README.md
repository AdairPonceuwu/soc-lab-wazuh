# Case 01 — Local User Creation & Privilege Escalation (Windows)

## Overview
This detection case documents the creation of a local user account on a Windows endpoint, followed by the addition of that account to the local **Administrators** group.

This behavior may indicate **privilege escalation** or **persistence**, commonly observed during post-compromise activity if not properly authorized.
The endpoint is monitored using **Wazuh**, leveraging Windows Security Event Logs.

---

## Detection Goal
Detect and analyze:
- Creation of a new local user account.
- Addition of that account to a privileged local group.

Determine whether the activity represents **legitimate administration** or **malicious escalation**.

---

## MITRE ATT&CK Mapping
- **T1136.001** – Create Account: Local Account
- **T1098** – Account Manipulation
- **TA0004** – Privilege Escalation
- **TA0003** – Persistence

---

## Endpoint Information
- **Hostname:** WIN10-ENDPOINT
- **IP Address:** 192.168.56.103
- **Operating System:** Windows 10 Pro

---

## Attack Simulation (Lab)
The following activity was executed in a controlled lab environment:

1. A new local user account was created.
2. The account was added to the local **Administrators** group.

This activity was performed for **educational and testing purposes only**.

---

## Detection
The following Windows Security Events were detected by Wazuh:

- **EventID 4720** — A local user account was created
- **EventID 4732** — A user was added to a security-enabled local group (Administrators)

---

## Queries Used
```
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4720
```

```
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4732
```

---

## Key Fields Observed
- **SubjectUserName** – Account that performed the action
- **TargetUserName** – Newly created or modified account
- **TargetDomainName**
- **ComputerName**
- **Timestamp**

These fields help identify who performed the action, which account was affected, and where it occurred.

---

## Analysis (SOC Triage)
This activity could indicate **privilege escalation or persistence** if not authorized.

Questions to validate:
- Is the subject user part of IT or Helpdesk?
- Was the action performed during business hours?
- Was the account creation followed by successful logons (EventID 4624)?
- Was the activity local or performed via remote access?
- Is the username consistent with organizational naming conventions?
- Has similar activity occurred on other endpoints?

---

## Severity
**Medium**

### Severity Rationale
Local user creation and admin assignment can be legitimate.
Severity should be escalated to **High** if:
- Performed by non-IT accounts
- Executed outside business hours
- Followed by suspicious authentication activity
- Observed across multiple endpoints

---

## False Positives & Tuning

### Potential False Positives
- IT administrators provisioning local accounts
- Break-glass or emergency administrative accounts
- Authorized maintenance activities

### Tuning Recommendations
- Allowlist known IT and administrative accounts
- Alert only when the subject user is not part of IT groups
- Correlate with remote logon events (RDP, SMB, WinRM)
- Increase severity when combined with persistence techniques

---

## Recommendations
- Validate whether the user creation was authorized.
- Disable or remove the account if suspicious.
- Review activity performed by the new account.
- Monitor authentication events related to the account.
- Search for similar activity across the environment.

---

## Evidence
Screenshots of the detected events and the active agent are included in this folder.

---

## Screenshots

### Agent Active
![Agent Active](./agent-active.png)

### EventID 4720 — User Created
![EventID 4720](./evidence-4720.png)

### EventID 4732 — Added to Administrators
![EventID 4732](./evidence-4732.png)

---

## Analyst Notes
Local account creation followed by administrative privilege assignment is a high-value SOC detection,
often associated with attacker persistence and privilege escalation during post-exploitation phases.

