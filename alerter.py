# alerter.py

from collections import defaultdict
from config import BRUTE_FORCE_THRESHOLD

def analyze_events(events: list[dict]) -> dict:
    """
    Takes a list of parsed events and produces:
    - A per-IP failure count
    - A list of IPs that crossed the brute force threshold
    - A summary of all event type counts
    - A list of privilege escalation events
    """
    failed_logins_by_ip = defaultdict(int)
    escalations = []
    event_type_counts = defaultdict(int)

    for event in events:
        etype = event["event_type"]
        event_type_counts[etype] += 1

        if etype == "FAILED_LOGIN":
            # groups[1] is the IP address captured by our regex
            ip = event["groups"][1]
            failed_logins_by_ip[ip] += 1

        elif etype in ("SUDO_ESCALATION", "FAILED_SU"):
            escalations.append({
                "line": event["line"],
                "type": etype,
                "detail": event["groups"],
                "raw": event["raw"],
            })

    # Flag IPs that exceeded the threshold
    flagged_ips = {
        ip: count
        for ip, count in failed_logins_by_ip.items()
        if count >= BRUTE_FORCE_THRESHOLD
    }

    return {
        "event_counts": dict(event_type_counts),
        "failed_logins_by_ip": dict(failed_logins_by_ip),
        "flagged_ips": flagged_ips,
        "escalations": escalations,
    }
