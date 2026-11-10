import argparse
from pathlib import Path
from log_reader import read_logs
from log_analyzer import analyze_logs
from report_generator import generate_report

parser = argparse.ArgumentParser(
    description="Analyze log files and generate a report."
)

parser.add_argument("filename", help="Name of the log file to analyze")

args = parser.parse_args()

file_path = Path(__file__).parent / args.filename
reports_folder = Path(__file__).parent / "Reports"
reports_folder.mkdir(exist_ok=True)
report_path = reports_folder / "report.txt"

lines = read_logs(file_path)

if lines is None:
    print("Analysis cancelled.")
    exit()
(events, failed_logins, failed_by_user, failed_by_ip, error_messages, ip_counts) = (
    analyze_logs(lines)
)

generate_report(
    report_path,
    events,
    failed_logins,
    failed_by_user,
    failed_by_ip,
    error_messages,
    ip_counts,
)
