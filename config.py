# config.py

# How many failed attempts from one IP triggers an alert
BRUTE_FORCE_THRESHOLD = 5

# Path to the log file to analyze
LOG_FILE_PATH = "logs/auth.log"

# Path to write the output report
OUTPUT_FILE_PATH = "output/report.json"

# Patterns the parser will look for (regex strings)
# Each entry is a tuple: (event_type_label, regex_pattern)
LOG_PATTERNS = [
    ("FAILED_LOGIN",  r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+)"),
    ("SUCCESSFUL_LOGIN", r"Accepted (?:password|publickey) for (\S+) from ([\d\.]+)"),
    ("SUDO_ESCALATION", r"sudo.*USER=root.*COMMAND=(.+)"),
    ("FAILED_SU",     r"FAILED su for (\S+) by (\S+)"),
    ("SESSION_OPENED", r"session opened for user (\S+)"),
    ("SESSION_CLOSED", r"session closed for user (\S+)"),
]
