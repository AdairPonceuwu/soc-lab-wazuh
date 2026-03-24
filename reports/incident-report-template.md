# Incident Report Template

Use this template to document detection cases and investigations in a consistent SOC-style format.

This template is designed for:

- lab validation
- portfolio documentation
- analyst workflow practice
- incident triage writeups

---

# Incident Report — [Case Title]

## 1. Executive Summary

Provide a short summary of what was detected, why it matters, and what the analyst concluded.

**Example:**  
A suspicious PowerShell execution was detected on the Windows endpoint `WIN10-ENDPOINT`. The command used `-NoProfile` and `-ExecutionPolicy Bypass`, which may indicate policy bypass or malicious execution. The activity was confirmed in Wazuh and reviewed as a high-priority event requiring analyst investigation.

---

## 2. Detection Details

- **Case Name:**  
- **Detection Source:** Wazuh
- **Detection Type:**  
- **Rule ID (if applicable):**  
- **Severity:**  
- **Date / Time Detected:**  
- **Hostname:**  
- **Endpoint IP:**  
- **User / Account Involved:**  
- **Operating System:** Windows 10 Pro

---

## 3. ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
|        |           |    |

Add multiple rows if needed.

---

## 4. Observed Activity

Describe exactly what activity was observed.

**Suggested points to include:**

- what event or behavior triggered the detection
- what command, logon, account change, or persistence action occurred
- whether the activity was isolated or part of a sequence
- whether there was follow-on activity

---

## 5. Relevant Telemetry

Document the logs and fields used in the investigation.

- **Log source:**  
- **Collection method:**  
- **Relevant Event IDs:**  
- **Important fields reviewed:**  

**Example fields:**

- `TargetUserName`
- `SubjectUserName`
- `IpAddress`
- `TaskName`
- `win.system.message`
- `Timestamp`

---

## 6. Queries Used

Include the main queries used during hunting or validation.

```text
# Query 1
```

```text
# Query 2
```

```text
# Query 3
```

---

## 7. Investigation Timeline

Document the sequence of events or analyst steps.

| Time | Event / Action | Notes |
|------|----------------|-------|
|      |                |       |

This can include:

- activity generation in the lab
- event validation in Wazuh
- rule troubleshooting
- alert confirmation
- remediation steps

---

## 8. Evidence

Document the supporting evidence collected during the investigation.

**Suggested evidence:**

- screenshots of alerts
- event detail screenshots
- query results
- endpoint command output
- rule validation output

### Evidence Files

- `./evidence/file-1.png`
- `./evidence/file-2.png`

---

## 9. Analyst Assessment

Provide the analyst’s judgment of the event.

**Suggested questions to answer:**

- Does the activity look legitimate or suspicious?
- Is the user or account expected?
- Is the timing normal or abnormal?
- Is the behavior consistent with the environment?
- Does this match known attacker behavior?
- Is more investigation required?

**Assessment:**  
Write your conclusion here.

---

## 10. Severity Rationale

Explain why the case was rated at its assigned severity.

**Example:**  
Severity was rated as **High** because repeated failed logons were followed by a successful authentication, increasing the likelihood of credential compromise and the need for immediate review.

---

## 11. False Positives

List realistic benign explanations.

**Example ideas:**

- administrative maintenance
- user password mistakes
- approved automation
- software installation activity
- lab testing

---

## 12. Tuning Recommendations

Document how the detection could be improved.

**Example ideas:**

- allowlist known users or task names
- add thresholding logic
- correlate with follow-on events
- reduce noise from service accounts
- increase severity when combined with persistence or remote access

---

## 13. Containment / Remediation

Describe what action was taken or what should be done next.

**Examples:**

- disable the account
- delete the scheduled task
- isolate the host
- reset credentials
- review related activity on nearby systems
- escalate to incident response

---

## 14. Verification

Document how remediation or validation was confirmed.

**Example:**  
The suspicious scheduled task was removed and verified using:

```text
schtasks /query /tn "WinPersistTest"
```

---

## 15. Lessons Learned

Capture what this case taught you.

**Example ideas:**

- validating telemetry first saves time
- native Windows logs still support strong detections
- stable rules matter more than overly complex ones
- some Wazuh detections require message-based matching because of parsing limitations

---

## 16. Reproduction Status

- [ ] Reproducible in current lab
- [ ] Detection validated
- [ ] Query validated
- [ ] Severity documented
- [ ] Evidence attached
- [ ] Remediation or verification documented

---

## 17. Related Files

Link related project files here.

**Example:**

- [Case README](../case-01/README.md)
- [Rule File](../detections/wazuh/local_rules.xml)
- [Query File](../queries/windows-auth-and-persistence.md)
- [ATT&CK Matrix](../docs/ATTACK-Coverage-Matrix.md)
