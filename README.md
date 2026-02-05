# SOC Lab — Wazuh SIEM (Windows Endpoint)

Personal SOC lab built using **Wazuh SIEM** to monitor a Windows endpoint, perform threat detection, and document security incidents following real-world SOC workflows.

This project focuses on **log validation, detection engineering, threat hunting, and incident documentation**, prioritizing stability and production-aware decisions over theoretical detections.

---

## Architecture

- **SIEM:** Wazuh 4.14.1 (All-in-One OVA)
- **Endpoint:** Windows 10 Pro (Wazuh Agent 4.14.1)
- **Log source:** Windows Security Event Log (WEF)
- **Network:** VirtualBox Host-Only (192.168.56.0/24)

---

## Detection Cases

Each case documents the full SOC workflow: detection logic, triage, validation, and lessons learned.

- [Case 01 — Local User Creation & Privilege Escalation](./case-1-user-admin/README.md)
- [Case 02 — Persistence via Scheduled Task](./case-2-persistence-scheduled-task/README.md)
- [Case 03 — Failed Logons / Brute Force](./case-3-failed-logons-bruteforce/README.md)
- [Case 04 — Suspicious PowerShell Execution (LOLBins)](./case-4-suspicious-powershell-execution/README.md)

---

## Documentation

Additional SOC-focused documentation is included to describe methodology and reusable investigation assets.

- [SOC Detection Methodology](./docs/SOC-Detection-Methodology.md)
- [Wazuh Rule Creation Notes](./docs/Wazuh_Rule_Creation_Notes.md)
- [Wazuh Query Cookbook](./docs/Wazuh_Query_Cookbook.md)

These documents reflect real SOC considerations such as:
- Log availability validation
- Rule inheritance (`if_sid`)
- Handling `no_full_log` limitations
- Stability-first detection design

---

## Skills Demonstrated

- Wazuh SIEM deployment and administration
- Windows Security Event analysis
- Threat hunting using DQL
- Detection engineering without Sysmon
- Custom Wazuh rule development
- MITRE ATT&CK mapping
- SOC-style incident triage and documentation
- Debugging and stabilizing SIEM rule failures

---

## Scope and Limitations

- This lab focuses on **Windows endpoint monitoring**
- Detection logic is designed using **native Windows logs**
- No Sysmon or EDR is used, reflecting constrained environments
- Linux detections are planned for future expansion

---

## Disclaimer

This project is for **educational and portfolio purposes only**.  
All activity was performed in an isolated lab environment.

---
