# SOC Lab — Wazuh SIEM (Windows Endpoint)

Personal SOC lab built using **Wazuh SIEM** to monitor a Windows endpoint, perform basic threat detection, and document triage cases aligned to SOC Tier 1.

## Architecture
- SIEM: Wazuh 4.14.1 (All-in-One OVA)
- Endpoint: Windows 10 Pro (Wazuh agent 4.14.1)
- Network: VirtualBox Host-Only (192.168.56.0/24)

## Cases
- [Case 01 — Local User Creation & Added to Administrators](./case-1-user-admin/README.md)

## Skills demonstrated
- SIEM setup (Wazuh)
- Windows Security Events analysis
- Basic threat hunting with DQL
- SOC-style incident documentation
