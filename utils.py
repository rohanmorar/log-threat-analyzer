# utils.py

import json
import os
from datetime import datetime

def ensure_output_dir(path: str):
    """Creates the output directory if it doesn't exists"""
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)

def write_json_report(data: dict, output_path: str):
    """Writes a directory to a formatted JSON file."""
    ensure_output_dir(output_path)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Report written to {output_path}")

def get_timestamp() -> str:
    """Returns a human-readable timestamp or report metadata."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
