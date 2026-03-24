# Documentation Index

This folder contains supporting documentation for the SOC lab beyond the individual detection cases.

Its purpose is to centralize reusable notes, methodology, detection engineering lessons, and ATT&CK mapping so the repository is easier to navigate from a SOC analyst, blue team, or recruiter perspective.

---

## Contents

### 1. [ATT&CK Coverage Matrix](./ATTACK-Coverage-Matrix.md)

Summarizes the current detection coverage of the lab using **MITRE ATT&CK**.

This document helps show:

- which techniques are currently covered
- which Windows event IDs support each case
- the current severity assigned to each scenario
- where future detection expansion is planned

---

### 2. [SOC Detection Methodology](./SOC-Detection-Methodology.md)

Documents the workflow used to build and validate detection logic in the lab.

This includes practices such as:

- validating telemetry before writing detections
- confirming raw event visibility in Wazuh
- identifying relevant fields and parent rules
- testing rule stability
- documenting tuning decisions and limitations

---

### 3. [Wazuh Rule Creation Notes](./Wazuh_Rule_Creation_Notes.md)

Contains practical notes related to custom Wazuh rule development.

This document is intended to support:

- rule troubleshooting
- understanding `if_sid`
- handling field matching issues
- dealing with `no_full_log`
- improving custom rule stability

---

### 4. [Wazuh Query Cookbook](./Wazuh_Query_Cookbook.md)

Provides example queries used to validate telemetry, hunt suspicious activity, and support case investigations in Wazuh.

This is useful for:

- authentication event hunting
- persistence-related event validation
- account creation review
- scheduled task investigation
- PowerShell process creation hunting

---

## How This Folder Supports the Project

The `docs/` folder exists to separate **supporting knowledge** from the main case studies.

While each `case-*` folder focuses on a specific detection scenario, this folder contains the reusable material that supports the project as a whole:

- methodology
- ATT&CK mapping
- rule engineering notes
- query references

This makes the repository easier to review and helps show that the lab is structured as a repeatable SOC learning project rather than just a collection of screenshots or isolated alerts.

---

## Recommended Reading Order

If you are reviewing the repository for the first time, the suggested order is:

1. Start with the main project [README](../README.md)
2. Review the [ATT&CK Coverage Matrix](./ATTACK-Coverage-Matrix.md)
3. Read the [SOC Detection Methodology](./SOC-Detection-Methodology.md)
4. Explore the individual detection cases in the `case-*` folders
5. Use the rule and query notes as supporting references

---

## Future Documentation

This folder may later include:

- severity classification guidance
- tuning methodology notes
- investigation playbooks
- detection validation checklists
- Linux-specific detection documentation
- correlation case design notes

---

## Goal

The goal of this folder is to make the lab more reusable, more reviewable, and more aligned with real SOC documentation practices.
