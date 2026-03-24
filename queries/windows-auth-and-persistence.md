# Windows Authentication and Persistence Queries

This file centralizes the main Wazuh / Discover queries used across the SOC lab.

The goal is to make hunting and validation easier by keeping the most useful Windows event queries in one place instead of scattering them across individual case documents.

---

## Notes

- These queries are based on **native Windows Security Event Logs**
- Telemetry is collected through the **Wazuh Agent via Windows Event Channel**
- Replace hostnames, usernames, or task names as needed for your own lab
- Some fields may vary slightly depending on parsing and Wazuh version

---

# 1. Host Scoping

Use these filters to scope queries to a specific endpoint before adding event conditions.

## Specific Host

```text
agent.name:"WIN10-ENDPOINT"
```

## Specific Host + IP

```text
agent.name:"WIN10-ENDPOINT" AND agent.ip:"192.168.56.103"
```

---

# 2. Account Creation and Privilege Changes

These queries support investigation of local user creation and privileged group membership changes.

## Event ID 4720 — Local User Account Created

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4720
```

## Event ID 4732 — User Added to Security-Enabled Local Group

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4732
```

## User Creation + Group Assignment

```text
agent.name:"WIN10-ENDPOINT" AND (data.win.system.eventID:4720 OR data.win.system.eventID:4732)
```

## Search by Target Username

```text
agent.name:"WIN10-ENDPOINT" AND data.win.eventdata.TargetUserName:"testuser"
```

## Search by Subject Username

```text
agent.name:"WIN10-ENDPOINT" AND data.win.eventdata.SubjectUserName:"Administrator"
```

### Use Case

Helpful for:

- validating account creation in Case 01
- confirming who performed the action
- investigating whether the created account was later modified or privileged

---

# 3. Scheduled Task Persistence

These queries support detection and review of scheduled task creation.

## Event ID 4698 — Scheduled Task Created

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4698
```

## Search by Task Name

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4698 AND data.win.eventdata.TaskName:"WinPersistTest"
```

## Search for Scheduled Task Events by Creator

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4698 AND data.win.eventdata.SubjectUserName:"Administrator"
```

### Use Case

Helpful for:

- validating Case 02
- checking which account created the task
- reviewing whether the task name appears benign or suspicious

---

# 4. Failed Logons / Brute Force

These queries support authentication hunting and brute force investigation.

## Event ID 4625 — Failed Logon

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4625
```

## Event ID 4624 — Successful Logon

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4624
```

## Failed + Successful Logons Together

```text
agent.name:"WIN10-ENDPOINT" AND (data.win.system.eventID:4625 OR data.win.system.eventID:4624)
```

## Failed Logons for a Specific User

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4625 AND data.win.eventdata.TargetUserName:"User1"
```

## Successful Logons for a Specific User

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4624 AND data.win.eventdata.TargetUserName:"User1"
```

## Failed Logons from a Specific Source IP

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4625 AND data.win.eventdata.IpAddress:"192.168.56.1"
```

## Authentication Sequence for a User

```text
agent.name:"WIN10-ENDPOINT" AND data.win.eventdata.TargetUserName:"User1" AND (data.win.system.eventID:4625 OR data.win.system.eventID:4624)
```

### Use Case

Helpful for:

- validating Case 03
- identifying repeated failed attempts
- checking whether a success followed the failures
- scoping to a user, IP, or workstation

---

# 5. PowerShell / Process Creation

These queries support suspicious PowerShell process creation hunting using native Windows logs.

## Event ID 4688 — Process Creation

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4688
```

## Event ID 4688 + PowerShell

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4688 AND data.win.system.message:"powershell.exe"
```

## PowerShell with NoProfile

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4688 AND data.win.system.message:"powershell.exe" AND data.win.system.message:"-NoProfile"
```

## PowerShell with ExecutionPolicy Bypass

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4688 AND data.win.system.message:"powershell.exe" AND data.win.system.message:"-ExecutionPolicy" AND data.win.system.message:"Bypass"
```

## Full Suspicious PowerShell Pattern

```text
agent.name:"WIN10-ENDPOINT" AND data.win.system.eventID:4688 AND data.win.system.message:"powershell.exe" AND data.win.system.message:"-NoProfile" AND data.win.system.message:"-ExecutionPolicy" AND data.win.system.message:"Bypass"
```

### Use Case

Helpful for:

- validating Case 04
- confirming suspicious PowerShell execution
- checking whether the rendered message contains the expected indicators
- supporting custom rule development when structured fields are limited

---

# 6. Cross-Case Investigation Queries

These queries are useful when reviewing related activity across multiple cases.

## Account Creation + Successful Logon

```text
agent.name:"WIN10-ENDPOINT" AND (data.win.system.eventID:4720 OR data.win.system.eventID:4624)
```

## Account Creation + Group Membership Change + Successful Logon

```text
agent.name:"WIN10-ENDPOINT" AND (data.win.system.eventID:4720 OR data.win.system.eventID:4732 OR data.win.system.eventID:4624)
```

## Failed Logons + Successful Logon + PowerShell

```text
agent.name:"WIN10-ENDPOINT" AND (data.win.system.eventID:4625 OR data.win.system.eventID:4624 OR data.win.system.eventID:4688)
```

## Privilege Changes + Scheduled Tasks

```text
agent.name:"WIN10-ENDPOINT" AND (data.win.system.eventID:4732 OR data.win.system.eventID:4698)
```

### Use Case

Helpful for:

- exploring multi-step attack scenarios
- building future correlation cases
- reviewing activity before writing a higher-confidence detection

---

# 7. Investigation Tips

When using these queries, it is usually helpful to:

- start with a single host filter
- validate that the expected event exists before refining further
- pivot by username, task name, source IP, or time window
- compare failed and successful activity close together in time
- review adjacent events around suspicious PowerShell or persistence activity

---

# 8. Planned Query Expansion

Future versions of this file may include:

- RDP-focused logon queries
- service creation queries
- remote administration activity
- Linux hunting queries
- Sysmon-based comparisons when available
