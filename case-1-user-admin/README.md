# Case 01 — Local User Creation & Privilege Escalation

## Summary
Detected a local user account creation and addition to the **Administrators** group on a Windows endpoint monitored by Wazuh.

## Endpoint
- Agent: WIN10-ENDPOINT
- IP: 192.168.56.103

## Evidence (Windows Security Events)
- EventID **4720** — User account created
- EventID **4732** — User added to a security-enabled local group (Administrators)

## Queries (DQL)
```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4720
