# Case 03 — Failed Logons / Brute Force (Windows)

## Overview
This detection case documents multiple failed authentication attempts followed by a successful logon on a Windows endpoint monitored by Wazuh.

This behavior is commonly associated with **brute force or password guessing attacks**, where an attacker attempts multiple credentials until successful access is achieved.

---

## Detection Goal
Detect and analyze:
- Repeated failed authentication attempts.
- Successful logon events following multiple failures.

Determine whether the activity represents **legitimate user error** or a **credential-based attack**.

---

## MITRE ATT&CK Mapping
- **T1110** – Brute Force
- **TA0006** – Credential Access
- **TA0001** – Initial Access

---

## Endpoint Information
- **Hostname:** WIN10-ENDPOINT
- **IP Address:** 192.168.56.103
- **Operating System:** Windows 10 Pro

---

## Attack Simulation (Lab)
The following activity was executed in a controlled lab environment:

1. Multiple failed logon attempts were generated against a user account.
2. A successful authentication occurred after repeated failures.

This activity was performed for **educational and testing purposes only**.

---

## Detection
The following Windows Security Events were detected by Wazuh:

- **EventID 4625** — Failed logon attempt
- **EventID 4624** — Successful logon

---

## Queries Used
```
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4625
```

```
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4624
```

---

## Key Fields Observed
The following fields are critical for investigation:

- **TargetUserName**
- **LogonType**
- **IpAddress / WorkstationName**
- **FailureReason**
- **ComputerName**
- **Timestamp**

These fields help determine **which account was targeted**, **from where**, and **how the authentication occurred**.

---

## Analysis (SOC Triage)
Multiple failed authentication attempts against the account `User1` in a short time window, followed by a successful logon, indicate a **potential brute force attack**.

During triage, the following should be validated:
- How many failed attempts occurred and within what timeframe?
- Did the successful logon originate from the same source IP?
- What logon type was used (interactive, RDP, network, service)?
- Is the account privileged or commonly targeted?
- Is similar activity observed on other endpoints or accounts?
- Did the successful logon lead to further suspicious activity?

---

## Severity
**High**

### Severity Rationale
- A successful logon following repeated failures strongly indicates credential compromise.
- Immediate investigation is required to prevent lateral movement or privilege escalation.

---

## False Positives & Tuning

### Potential False Positives
- Users repeatedly mistyping passwords
- Cached credentials after password changes
- Automated services with misconfigured credentials

### Tuning Recommendations
- Alert when failures exceed a defined threshold within a time window
- Correlate failed and successful logons by user and source IP
- Reduce noise by excluding known service accounts
- Increase severity when followed by privileged actions

---

## Recommendations
- Reset the affected account password immediately.
- Investigate the source IP or workstation involved.
- Enforce account lockout policies.
- Enable Multi-Factor Authentication (MFA).
- Monitor for lateral movement or privilege escalation.

---

## Evidence
Screenshots showing multiple failed logons and the subsequent successful authentication are included in this folder.

---

## Screenshots

### Failed Logons — EventID 4625 (Timeline)
![EventID 4625 Timeline](./evidence-4625-timeline.png)

### Failed Logon — EventID 4625 (Detail)
![EventID 4625 Detail](./evidence-4625.png)

### Successful Logon — EventID 4624
![EventID 4624](./evidence-4624.png)

---

## Analyst Notes
Failed logons followed by a successful authentication represent a **high-confidence credential attack pattern**.
Correlating authentication events over time is critical to accurately identify brute force activity.

