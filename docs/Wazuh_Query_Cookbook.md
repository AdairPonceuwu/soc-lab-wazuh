# Wazuh Query Cookbook

This document contains commonly used Wazuh queries for SOC investigations.
All queries are tested against Windows Event Channel data.

# Case 01
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4720  # Added to Administrators
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4732  # Added to Administrators

# Case 02 — Persistence (Scheduled Task)
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4698  # Scheduled task created

# Case 03 — Failed Logons / Brute Force
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4625  # Failed logon
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4624  # Successful logon

# RDP / Remote Access
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4624 AND data.win.eventdata.logonType:10  # RDP logon
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4625 AND data.win.eventdata.logonType:10  # RDP failed

# PowerShell activity
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4104  # Script Block Logging
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4688
