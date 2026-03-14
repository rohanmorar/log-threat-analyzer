# Log Threat Analyzer

A lightweight SOC automation tool written in Python that parses Linux
authentication logs, detects brute-force attacks through IP-based threshold
correlation, flags privilege escalation events, and delivers email alerts
when threats are found — running autonomously on a scheduled cron job.

Built as a portfolio project to demonstrate security automation, log analysis,
and production-grade Python practices.

---

## Why This Exists

Manual log review doesn't scale. A server generating thousands of auth events
per day makes it practically impossible for a human analyst to catch a
brute-force attempt in time. This tool mirrors the core logic of enterprise
SIEM platforms like Splunk and Elastic SIEM — in a lightweight, portable,
fully auditable Python script.

**Key production concepts demonstrated:**
- Signal-to-noise reduction via regex-based pattern filtering
- Temporal correlation (per-IP failure counting against a tunable threshold)
- Structured output (JSON) designed for downstream consumption
- Separation of concerns across modular files
- Credential management via environment variables
- Automated scheduling via cron
- Defensive coding with explicit error handling

---

## Features

| Feature | Detail |
|---|---|
| Multi-pattern log parsing | Detects failed logins, successful logins, sudo escalations, failed su attempts |
| Brute-force detection | Flags any IP exceeding a configurable failed login threshold |
| Privilege escalation flagging | Catches sudo and su abuse events |
| Email alerting | Sends Gmail alerts only when threats are detected |
| JSON report output | Structured, timestamped report written on every run |
| CLI arguments | Runtime control over log path, output path, and threshold |
| Cron integration | Runs autonomously every hour against the live system log |
| Unit tested | 7 pytest tests covering happy path, edge cases, and failure modes |

---

## Project Structure
```
log-parser/
├── logs/
│   ├── auth.log            # Simulated test log data
│   └── cron.log            # Auto-generated run history
├── output/
│   └── report.json         # Latest analysis output
├── tests/
│   └── test_analyzer.py    # pytest unit tests
├── main.py                 # Entry point and CLI argument handling
├── parser.py               # Regex-based log parsing
├── alerter.py              # Threshold correlation and event analysis
├── notifier.py             # Email alert delivery
├── utils.py                # Shared helper functions
├── config.py               # All tunable settings
├── run_analyzer.sh         # Cron wrapper script
├── .env.example            # Credential template (safe to commit)
├── requirements.txt        # Locked dependencies
└── README.md
```

---

## Setup

### 1. Clone the repository
```bash
git clone git@github.com:yourusername/log-threat-analyzer.git
cd log-threat-analyzer
```

### 2. Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure credentials
```bash
cp .env.example .env
nano .env
```

Fill in your Gmail address and App Password:
```
ALERT_EMAIL_SENDER=yourgmail@gmail.com
ALERT_EMAIL_PASSWORD=your_app_password_here
ALERT_EMAIL_RECIPIENT=yourgmail@gmail.com
```

> **Note:** Gmail App Passwords require 2FA to be enabled on your account.
> Generate one at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
> Your real Gmail password is never used or stored.

---

## Usage

### Run manually against the simulated test log
```bash
python3 main.py --logfile logs/auth.log
```

### Run against the real system log
```bash
python3 main.py --logfile /var/log/auth.log
```

### Custom threshold and output path
```bash
python3 main.py --logfile /var/log/auth.log --threshold 3 --output output/custom.json
```

### View all options
```bash
python3 main.py --help
```

---

## Automating with Cron

The tool runs every hour via cron using the included shell wrapper.

### 1. Update the project path in the wrapper script
```bash
nano run_analyzer.sh
```
Set `PROJECT_DIR` to your absolute project path.

### 2. Make it executable
```bash
chmod +x run_analyzer.sh
```

### 3. Register the cron job
```bash
crontab -e
```
Add this line:
```
0 * * * * /home/yourusername/projects/log-parser/run_analyzer.sh
```

### 4. Verify cron is active
```bash
sudo systemctl status cron
```

Run history is appended to `logs/cron.log` on every execution.

---

## Running Tests
```bash
pytest tests/ -v
```

Expected output:
```
tests/test_analyzer.py::test_brute_force_ip_is_flagged          PASSED
tests/test_analyzer.py::test_ip_below_threshold_is_not_flagged  PASSED
tests/test_analyzer.py::test_failed_login_count_is_accurate     PASSED
tests/test_analyzer.py::test_escalation_events_are_captured     PASSED
tests/test_analyzer.py::test_empty_log_returns_empty_results    PASSED
tests/test_analyzer.py::test_parse_log_file_missing_file        PASSED
tests/test_analyzer.py::test_custom_threshold_respected         PASSED

7 passed
```

---

## Sample Output

### Terminal
```
╔══════════════════════════════════════╗
║       LOG THREAT ANALYZER v1.0       ║
║       SOC Automation Toolkit         ║
╚══════════════════════════════════════╝

[*] Analyzing: /var/log/auth.log
[*] Brute force threshold: 5 attempts

[*] Total events matched: 20

========================================
  EVENT SUMMARY
========================================
  FAILED_LOGIN              14
  SUCCESSFUL_LOGIN           3
  SUDO_ESCALATION            1
  FAILED_SU                  1

========================================
  FAILED LOGINS BY IP
========================================
  192.168.1.50         7 attempts  ⚠ FLAGGED
  198.51.100.9         5 attempts  ⚠ FLAGGED
  203.0.113.7          3 attempts

========================================
  ⚠  PRIVILEGE ESCALATION EVENTS
========================================
  Line 12: [SUDO_ESCALATION] ...
  Line 13: [FAILED_SU] ...

[+] Report written to: output/report.json
[+] Alert email sent to yourgmail@gmail.com
```

### Email Alert
```
Subject: [ALERT] Threats Detected in auth.log

==================================================
  LOG THREAT ANALYZER — ALERT REPORT
==================================================
  Timestamp : 2025-01-15 02:00:00
  Log File  : /var/log/auth.log
  Threshold : 5 attempts

⚠ FLAGGED IPs (brute force detected):
  192.168.1.50         7 failed attempts
  198.51.100.9         5 failed attempts

⚠ PRIVILEGE ESCALATION EVENTS:
  Line 12: [SUDO_ESCALATION] sudo: deploy USER=root COMMAND=/bin/bash
  Line 13: [FAILED_SU] FAILED su for root by www-data
==================================================
```

### JSON Report (`output/report.json`)
```json
{
    "meta": {
        "timestamp": "2025-01-15 02:00:00",
        "log_file": "/var/log/auth.log",
        "threshold_used": 5
    },
    "results": {
        "event_counts": {
            "FAILED_LOGIN": 14,
            "SUCCESSFUL_LOGIN": 3,
            "SUDO_ESCALATION": 1,
            "FAILED_SU": 1
        },
        "failed_logins_by_ip": {
            "192.168.1.50": 7,
            "203.0.113.7": 3,
            "198.51.100.9": 5
        },
        "flagged_ips": {
            "192.168.1.50": 7,
            "198.51.100.9": 5
        },
        "escalations": [...]
    }
}
```

---

## Detection Logic

### Brute Force Detection
Any IP address that generates failed login attempts equal to or greater than
the configured threshold (default: 5) within the analyzed log window is added
to the `flagged_ips` list and triggers an email alert.

This mirrors the core detection logic of SIEM correlation rules, where a
single event is noise but repeated events from the same source become a signal.

### Privilege Escalation Detection
Any log line matching `sudo USER=root` or `FAILED su` patterns is captured
as an escalation event regardless of threshold. A single instance is enough
to warrant investigation.

---

## Extending This Tool

Some natural next steps for expanding capability:

- **Windows support** — add a PowerShell companion script using `Get-WinEvent`
  to parse Windows Security Event Log (Event ID 4625 for failed logins)
- **Apache/Nginx support** — add patterns for `access.log` to detect
  directory traversal or vulnerability scanning
- **IP geolocation** — enrich flagged IPs with country/ASN data using
  the `ipwhois` library
- **Automatic blocking** — pipe flagged IPs to `iptables` to drop traffic
  in real time
- **Dashboard** — export JSON reports to a local web dashboard using Flask

---

## Environment

- OS: Kali Linux (tested on 2024.x)
- Python: 3.11+
- Key libraries: `colorama`, `python-dotenv`, `pytest`

---

## Author

**Rohan** — Aspiring SOC Analyst  
Built as part of a hands-on security automation learning path.  
[GitHub](https://github.com/rohanmorar)
