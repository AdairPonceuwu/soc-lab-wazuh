# Reports Index

This folder contains reusable reporting material for the SOC lab.

Its purpose is to document detection cases and investigations in a format that reflects a practical **SOC analyst workflow**, rather than leaving each case only as a technical walkthrough.

---

## Contents

### 1. [Incident Report Template](./incident-report-template.md)

This template is intended to standardize how cases are documented from an analyst perspective.

It can be used for:

- lab validation
- incident-style writeups
- portfolio documentation
- analyst triage practice
- structured investigation notes

---

## Why This Folder Exists

The project is built around more than just detections and screenshots.

A real SOC workflow usually includes:

- alert review
- triage decisions
- evidence collection
- severity assessment
- containment recommendations
- post-incident lessons learned

This folder helps represent that part of the workflow.

---

## How It Relates to the Rest of the Repository

The repository is structured so that different folders represent different parts of the SOC process:

- `case-*` → individual detection cases and scenario walkthroughs
- `detections/wazuh/` → reusable custom Wazuh detection rules
- `queries/` → hunting and validation queries
- `docs/` → methodology, ATT&CK mapping, and supporting documentation
- `reports/` → structured incident reporting material

This makes the project easier to review and helps show that the lab is organized around repeatable security operations practices.

---

## Suggested Use

A practical way to use this folder is:

1. review a case in a `case-*` folder
2. validate the evidence and query results
3. use the incident report template to summarize the investigation
4. record severity, analyst assessment, and next actions
5. store future case-specific reports here if needed

---

## Future Expansion

This folder may later include:

- case-specific incident reports
- executive summary examples
- severity classification examples
- triage decision notes
- remediation validation examples

---

## Goal

The goal of this folder is to make the repository look and function more like a real SOC project by including the reporting layer that normally follows detection and investigation.
