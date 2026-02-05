# SOC Detection Methodology

This document describes the methodology used to design, validate, and document detection use cases in this lab.
It reflects a SOC-oriented, production-aware approach rather than a theoretical or tool-specific guide.

---

## 1. Detection-First Mindset

Every detection starts with a question, not a rule.

Examples:
- What attacker behavior am I trying to detect?
- What telemetry do I realistically have?
- What is the acceptable false-positive rate?

Detections are built to answer operational security questions, not to match isolated events.

---

## 2. Validate Log Availability First

Before writing any detection logic:

- Confirm the event exists on the endpoint
- Confirm the event is ingested by the SIEM
- Inspect raw events directly (`alerts.json`)

No rule is written unless the underlying telemetry is confirmed.

---

## 3. Identify the Base (Parent) Rule

Wazuh rules are hierarchical.
Every custom rule must inherit from the correct parent rule using `if_sid`.

Process:
1. Identify the rule that initially triggers
2. Inspect its options (e.g., `no_full_log`)
3. Design the custom rule around those constraints

Incorrect inheritance results in silent detection failures.

---

## 4. Field Reliability Assessment

Not all event fields are equally reliable.

Priority order:
1. Stable system fields (EventID, provider name)
2. Rendered event messages
3. Structured fields (only when full logs are available)

When `no_full_log` is present, structured fields are treated as unreliable.

---

## 5. Stability Over Precision

In production SOC environments:
- Stable detections are preferred over complex parsing
- Rules must never impact platform availability
- Incremental detection logic is favored

All rules are validated using:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

---

## 6. Severity Assignment

Severity is assigned based on:
- MITRE ATT&CK technique
- Potential attacker impact
- Operational context (lab vs production)

Severity is intentionally conservative to reduce alert fatigue.

---

## 7. MITRE ATT&CK Mapping

MITRE mapping is applied after detection logic is validated.

MITRE is used for:
- Contextual enrichment
- Reporting
- Coverage tracking

MITRE mapping never replaces detection logic.

---

## 8. Documentation as a Detection Requirement

A detection is not complete without documentation.

Each case documents:
- Detection logic
- Assumptions
- Limitations
- Validation steps
- Lessons learned

Documentation is treated as a core deliverable.

---

## 9. Continuous Improvement

Detections are reviewed when:
- New telemetry becomes available
- False positives are identified
- Detection coverage is expanded

Detection engineering is an iterative process.

---
