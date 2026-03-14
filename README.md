# Log Threat Analyzer

A Python-based SOC automation tool that parses Linux auth logs,
detects brute-force attempts through temporal correlation, and
flags privilege escalation events.

## Features
- Regex-based multi-pattern log parsing
- Configurable brute-force threshold detection
- Privilege escalation event flagging
- Structured JSON report output
- Color-coded terminal summary

## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python3 main.py
```

## Configuration
All tunable parameters (thresholds, file paths, patterns) live in `config.py`.
