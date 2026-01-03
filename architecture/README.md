
# SOC Lab Architecture

This document describes the architecture of the personal SOC lab built using Wazuh SIEM.

## Components

- **SIEM:** Wazuh 4.14.1 (All-in-One)
- **Endpoint:** Windows 10 Pro with Wazuh Agent
- **Hypervisor:** VirtualBox
- **Network:** Host-Only Network (192.168.56.0/24)

## Architecture Overview

The SOC lab consists of a centralized Wazuh SIEM monitoring a Windows endpoint.
The Wazuh agent installed on the endpoint collects Windows Security Events
and forwards them to the Wazuh Manager for analysis and correlation.

## Network Design

- Wazuh SIEM IP: 192.168.56.101
- Windows Endpoint IP: 192.168.56.103
- Communication ports:
  - 1514/UDP (events)
  - 1515/TCP (agent registration)

All systems are connected through a VirtualBox Host-Only network, simulating
an internal corporate environment.

## Data Flow

1. User activity occurs on the Windows endpoint.
2. Windows generates Security Events.
3. Wazuh Agent collects and forwards the events.
4. Wazuh SIEM processes and stores the data.
5. Analyst reviews events using the Wazuh Dashboard.

## Purpose of This Architecture

This lab simulates a basic SOC Tier 1 environment focused on:
- Log collection
- Event analysis
- Incident triage
- Security visibility
