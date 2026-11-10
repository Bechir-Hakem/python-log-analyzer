def generate_report(
    report_path,
    events,
    failed_logins,
    failed_by_user,
    failed_by_ip,
    error_messages,
    ip_counts
):
    # Identify suspicious users
    suspicious_users = []

    for username, count in failed_by_user.items():
        if count >= 4:
            suspicious_users.append((username, count))

    # Identify suspicious IPs
    suspicious_ips = []

    for ip, count in failed_by_ip.items():
        if count >= 4:
            suspicious_ips.append((ip, count))

    # Sort results
    sorted_errors = sorted(
        error_messages.items(),
        key=lambda item: item[1],
        reverse=True
    )

    sorted_users = sorted(
        failed_by_user.items(),
        key=lambda item: item[1],
        reverse=True
    )

    sorted_ips = sorted(
        ip_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )

    sorted_failed_ips = sorted(
        failed_by_ip.items(),
        key=lambda item: item[1],
        reverse=True
    )

    # Generate report
    with open(report_path, "w", encoding="utf-8") as report:

        report.write("========== LOG ANALYSIS REPORT ==========\n\n")

        report.write("EVENT SUMMARY\n")

        for event, count in events.items():
            report.write(f"{event}: {count}\n")

        report.write("\nFAILED LOGINS\n")
        report.write(f"Total: {failed_logins}\n")

        report.write("\nFAILED LOGINS BY USER\n")

        for username, count in sorted_users:
            report.write(f"{username}: {count}\n")

        report.write("\nFAILED LOGINS BY IP\n")

        for ip, count in sorted_failed_ips:
            report.write(f"{ip}: {count}\n")

        report.write("\nERROR MESSAGES (MOST FREQUENT FIRST)\n")

        for message, count in sorted_errors:
            report.write(f"{message}: {count}\n")

        report.write("\nIP ADDRESS ACTIVITY\n")

        for ip, count in sorted_ips:
            report.write(f"{ip}: {count}\n")

        report.write("\nSUSPICIOUS USERS\n")

        if suspicious_users:
            for username, count in suspicious_users:
                report.write(f"{username}: {count} failed attempts\n")
        else:
            report.write("No suspicious users detected.\n")

        report.write("\nSUSPICIOUS IP ADDRESSES\n")

        if suspicious_ips:
            for ip, count in suspicious_ips:
                report.write(f"{ip}: {count} failed attempts\n")
        else:
            report.write("No suspicious IP addresses detected.\n")

        report.write("\n=========================================\n")

    print("Report successfully generated!")