# main.py

from colorama import Fore, Style, init
from parser import parse_log_file
from alerter import analyze_events
from utils import write_json_report, get_timestamp
from config import LOG_FILE_PATH, OUTPUT_FILE_PATH, BRUTE_FORCE_THRESHOLD

init(autoreset=True)  # colorama setup

def print_banner():
    print(Fore.CYAN + """
╔══════════════════════════════════════╗
║       LOG THREAT ANALYZER v1.0       ║
║       SOC Automation Toolkit         ║
╚══════════════════════════════════════╝
""")

def main():
    print_banner()
    print(f"[*] Analyzing: {LOG_FILE_PATH}")
    print(f"[*] Brute force threshold: {BRUTE_FORCE_THRESHOLD} attempts\n")

    # Step 1: Parse the log file into structured events
    events = parse_log_file(LOG_FILE_PATH)
    print(f"[*] Total events matched: {len(events)}")

    # Step 2: Run analysis and correlation
    results = analyze_events(events)

    # Step 3: Print human-readable summary to terminal
    print("\n" + "="*40)
    print(Fore.WHITE + "  EVENT SUMMARY")
    print("="*40)
    for event_type, count in results["event_counts"].items():
        color = Fore.RED if "FAIL" in event_type else Fore.GREEN
        print(f"  {color}{event_type:<25}{Style.RESET_ALL} {count}")

    print("\n" + "="*40)
    print(Fore.WHITE + "  FAILED LOGINS BY IP")
    print("="*40)
    for ip, count in results["failed_logins_by_ip"].items():
        flagged = ip in results["flagged_ips"]
        color = Fore.RED if flagged else Fore.YELLOW
        flag_label = "  ⚠ FLAGGED" if flagged else ""
        print(f"  {color}{ip:<20} {count} attempts{flag_label}{Style.RESET_ALL}")

    if results["escalations"]:
        print("\n" + "="*40)
        print(Fore.RED + "  ⚠  PRIVILEGE ESCALATION EVENTS")
        print("="*40)
        for e in results["escalations"]:
            print(f"  Line {e['line']}: [{e['type']}] {e['raw']}")

    # Step 4: Write structured JSON report
    report = {
        "meta": {
            "timestamp": get_timestamp(),
            "log_file": LOG_FILE_PATH,
            "threshold_used": BRUTE_FORCE_THRESHOLD,
        },
        "results": results,
    }
    write_json_report(report, OUTPUT_FILE_PATH)

if __name__ == "__main__":
    main()
