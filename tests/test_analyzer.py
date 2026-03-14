# tests/test_analyzer.py

import sys
import os

# This lets Python find our modules from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from parser import parse_log_file
from alerter import analyze_events

# ─────────────────────────────────────────────
# Fixtures — reusable fake data for tests
# ─────────────────────────────────────────────

SAMPLE_EVENTS_BRUTE_FORCE = [
    {"line": i, "event_type": "FAILED_LOGIN", "raw": f"line {i}", "groups": ("root", "10.0.0.1")}
    for i in range(6)  # 6 failed logins from same IP
]

SAMPLE_EVENTS_BELOW_THRESHOLD = [
    {"line": i, "event_type": "FAILED_LOGIN", "raw": f"line {i}", "groups": ("admin", "10.0.0.2")}
    for i in range(3)  # only 3 — should NOT be flagged at threshold 5
]

SAMPLE_EVENTS_ESCALATION = [
    {
        "line": 10,
        "event_type": "SUDO_ESCALATION",
        "raw": "sudo: deploy TTY=pts/0 USER=root COMMAND=/bin/bash",
        "groups": ("/bin/bash",),
    }
]

# ─────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────

def test_brute_force_ip_is_flagged():
    """An IP with attempts >= threshold must appear in flagged_ips."""
    results = analyze_events(SAMPLE_EVENTS_BRUTE_FORCE, threshold=5)
    assert "10.0.0.1" in results["flagged_ips"], \
        "Expected 10.0.0.1 to be flagged but it wasn't"

def test_ip_below_threshold_is_not_flagged():
    """An IP with attempts below threshold must NOT appear in flagged_ips."""
    results = analyze_events(SAMPLE_EVENTS_BELOW_THRESHOLD, threshold=5)
    assert "10.0.0.2" not in results["flagged_ips"], \
        "Expected 10.0.0.2 to NOT be flagged but it was"

def test_failed_login_count_is_accurate():
    """The count of failed logins per IP must match the input exactly."""
    results = analyze_events(SAMPLE_EVENTS_BRUTE_FORCE, threshold=5)
    assert results["failed_logins_by_ip"]["10.0.0.1"] == 6

def test_escalation_events_are_captured():
    """Sudo escalation events must appear in the escalations list."""
    results = analyze_events(SAMPLE_EVENTS_ESCALATION, threshold=5)
    assert len(results["escalations"]) == 1
    assert results["escalations"][0]["type"] == "SUDO_ESCALATION"

def test_empty_log_returns_empty_results():
    """Passing an empty event list should return zeroed-out results gracefully."""
    results = analyze_events([], threshold=5)
    assert results["flagged_ips"] == {}
    assert results["escalations"] == []
    assert results["event_counts"] == {}

def test_parse_log_file_missing_file():
    """Parser should handle a missing file without crashing."""
    events = parse_log_file("logs/does_not_exist.log")
    assert events == [], "Expected empty list for missing file"

def test_custom_threshold_respected():
    """Lowering threshold to 2 should flag an IP with 3 attempts."""
    results = analyze_events(SAMPLE_EVENTS_BELOW_THRESHOLD, threshold=2)
    assert "10.0.0.2" in results["flagged_ips"]
