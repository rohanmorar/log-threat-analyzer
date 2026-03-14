# parser.py

import re
from config import LOG_FILE_PATH, LOG_PATTERNS

def parse_log_file(filepath: str = LOG_FILE_PATH) -> list[dict]:
    """
    Reads a log file and extracts structured events based on
    patterns defined in config.py.

    Returns a list of event dictionaries.
    """
    events = []

    try:
        with open(filepath, "r") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                for event_type, pattern in LOG_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        event = {
                            "line": line_number,
                            "event_type": event_type,
                            "raw": line,
                            "groups": match.groups()
                        }
                        events.append(event)
                        break # one event type per line
    except FileNotFoundError:
         print(f"[ERROR] Log file not found: {filepath}")
    except PermissionError:
         print(f"[ERROR] Permission denied reading: {filepath}")

    return events

