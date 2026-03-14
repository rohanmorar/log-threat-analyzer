# main.py

import argparse
from colorama import Fore, Style, init
from parser import parse_log_file
from alerter import analyze_events
from utils import write_json_report, get_timestamp
from config import LOG_FILE_PATH, OUTPUT_FILE_PATH, BRUTE_FORCE_THRESHOLD
from notifier import send_alert

init(autoreset=True)

def print_banner():
    print(Fore.CYAN + """
╔══════════════════════════════════════╗
║       LOG THREAT ANALYZER v1.0       ║
║       SOC Automation Toolkit         ║
╚══════════════════════════════════════╝
""")

def get_args():
    parser = argparse.ArgumentParser(
        description="Analyze Linux auth logs for brute-force and escalation events."
    )
    parser.add_argument(
        "--logfile",
        type=str,
        default=LOG_FILE_PATH,
        help=f"Path to the log file to analyze (default: {LOG_FILE_PATH})"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=OUTPUT_FILE_PATH,
        help=f"Path to write the JSON report (default: {OUTPUT_FILE_PATH})"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=BRUTE_FORCE_THRESHOLD,
        help=f"Failed login attempts before flagging an IP (default: {BRUTE_FORCE_THRESHOLD})"
    )
    return parser.parse_args()

def main():
    print_banner()
    args = get_args()

    print(f"[*] Analyzing: {args.logfile}")
    print(f"[*] Brute force threshold: {args.threshold} attempts\n")

    events = parse_log_file(args.logfile)
    print(f"[*] Total events matched: {len(events)}")

    results = analyze_events(events, threshold=args.threshold)

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

    report = {
        "meta": {
            "timestamp": get_timestamp(),
            "log_file": args.logfile,
            "threshold_used": args.threshold,
        },
        "results": results,
    }
    write_json_report(report, args.output)

    send_alert(results, args.logfile, args.threshold)

if __name__ == "__main__":
    main()
