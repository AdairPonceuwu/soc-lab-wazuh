# Wazuh Rule Creation Notes (SOC Analyst Guide)

## Key Principles

### Inspect Raw Events
Always inspect `alerts.json` before writing rules.

### Understand Parent Rules
Correct `if_sid` usage is mandatory for rule inheritance.

### Handle no_full_log Rules
If a rule uses `no_full_log`, rely on `win.system.message` instead of structured fields.

### Validate Continuously
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

### Keep a Placeholder Rule
Never leave a rule group empty.

### Document Decisions
SOC-grade detections require documentation of assumptions and limitations.
