# SOC Lab Architecture

This document describes the current architecture of the personal SOC lab built using Wazuh SIEM.

## Components

- **SIEM:** Wazuh 4.14.1 (All-in-One)
- **Endpoint:** Windows 10 Home Single Language (`WS-01`) with Wazuh Agent
- **Hypervisor:** VirtualBox
- **Additional Telemetry:**
  - Sysmon
  - PowerShell Script Block Logging

## Architecture Overview

The SOC lab consists of a centralized Wazuh SIEM monitoring a Windows endpoint with enhanced telemetry.

The Wazuh agent installed on the endpoint collects and forwards multiple Windows event channels to the Wazuh Manager for analysis and correlation.

These telemetry sources currently include:

- Windows Security Event Log
- Microsoft-Windows-Sysmon/Operational
- Microsoft-Windows-PowerShell/Operational

This architecture now provides richer endpoint visibility than the initial single-log-source design.

## Network Design

The lab currently uses a mixed VirtualBox network design:

- **Wazuh Dashboard / management access:** `192.168.56.101`
- **Wazuh Manager IP used by the agent:** `192.168.0.102`
- **Windows Endpoint:** `WS-01`

### Communication Ports

- `1514/TCP` — agent event communication
- `1515/TCP` — agent registration / enrollment
- `443/TCP` — Wazuh web dashboard access

This setup reflects the practical lab configuration used to allow the physical Windows endpoint to communicate successfully with the virtualized Wazuh server.

## Data Flow

1. User activity occurs on the Windows endpoint (`WS-01`).
2. Windows generates security-relevant events from multiple sources.
3. Sysmon records process and host telemetry.
4. PowerShell Script Block Logging records script content.
5. Wazuh Agent collects these events from Windows Event Channels.
6. Wazuh SIEM processes, stores, and correlates the data.
7. The analyst reviews alerts and events in the Wazuh Dashboard.

## Telemetry Sources

The current lab architecture uses the following endpoint telemetry:

- **Windows Security Event Log**
  - account activity
  - logon/logoff events
  - security-relevant Windows events

- **Sysmon**
  - process creation
  - file creation
  - registry activity
  - other enriched endpoint telemetry

- **PowerShell Script Block Logging**
  - executed script content
  - PowerShell command visibility
  - script block context for investigations

## Purpose of This Architecture

This lab now simulates a more realistic SOC Tier 1 / junior detection engineering environment focused on:

- Log collection
- Event analysis
- Incident triage
- Endpoint visibility
- Telemetry correlation
- Investigation of suspicious PowerShell activity

## Current Architecture Maturity

Compared to the initial lab version, this architecture now includes:

- enriched endpoint telemetry
- a physical monitored endpoint
- PowerShell visibility beyond native process creation logs
- Sysmon-based host telemetry for stronger investigations
- event correlation between process execution and script content
