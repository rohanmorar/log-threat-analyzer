# notifier.py

import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from utils import get_timestamp

load_dotenv()

SENDER = os.getenv("ALERT_EMAIL_SENDER")
PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD")
RECIPIENT = os.getenv("ALERT_EMAIL_RECIPIENT")


def build_email_body(results: dict, log_file: str, threshold: int) -> str:
    """Builds a plain-text email body from analysis results."""
    lines = []
    lines.append("=" * 50)
    lines.append("  LOG THREAT ANALYZER — ALERT REPORT")
    lines.append("=" * 50)
    lines.append(f"  Timestamp : {get_timestamp()}")
    lines.append(f"  Log File  : {log_file}")
    lines.append(f"  Threshold : {threshold} attempts")
    lines.append("")

    # Flagged IPs
    if results.get("flagged_ips"):
        lines.append("⚠ FLAGGED IPs (brute force detected):")
        for ip, count in results["flagged_ips"].items():
            lines.append(f"  {ip:<20} {count} failed attempts")
    else:
        lines.append("✓ No IPs exceeded the brute force threshold.")

    lines.append("")

    # Escalation events
    if results.get("escalations"):
        lines.append("⚠ PRIVILEGE ESCALATION EVENTS:")
        for e in results["escalations"]:
            lines.append(f"  Line {e['line']}: [{e['type']}] {e['raw']}")
    else:
        lines.append("✓ No privilege escalation events detected.")

    lines.append("")
    lines.append("=" * 50)
    lines.append("Full JSON report written to output/report.json")

    return "\n".join(lines)


def should_alert(results: dict) -> bool:
    """Only send an email if there's actually something to report."""
    return bool(results.get("flagged_ips")) or bool(results.get("escalations"))


def send_alert(results: dict, log_file: str, threshold: int):
    """
    Sends an email alert if threats were detected.
    Silently skips if nothing was flagged.
    """
    if not should_alert(results):
        print("[*] No threats detected. Email alert skipped.")
        return

    if not all([SENDER, PASSWORD, RECIPIENT]):
        print("[ERROR] Email credentials missing from .env file.")
        return

    subject = f"[ALERT] Threats Detected in {os.path.basename(log_file)}"
    body = build_email_body(results, log_file, threshold)

    msg = MIMEMultipart()
    msg["From"] = SENDER
    msg["To"] = RECIPIENT
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER, PASSWORD)
            server.sendmail(SENDER, RECIPIENT, msg.as_string())
        print(f"[+] Alert email sent to {RECIPIENT}")
    except smtplib.SMTPAuthenticationError:
        print("[ERROR] Gmail authentication failed. Check your App Password in .env")
    except smtplib.SMTPException as e:
        print(f"[ERROR] Failed to send email: {e}")
