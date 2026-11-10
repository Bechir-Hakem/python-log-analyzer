import re 
def is_valid_ip(ip_address):

    if not isinstance(ip_address, str):
        return False

    numbers = ip_address.split(".")

    valid = True

    # An IPv4 address must have exactly 4 groups
    if len(numbers) != 4:
        valid = False

    for number in numbers:
        # Reject empty groups
        if not number:
            valid = False
            continue

        try:
            value = int(number)

            # Each group must be between 0 and 255
            if value < 0 or value > 255:
                valid = False

        except ValueError:
            valid = False

    return valid

def analyze_logs(lines):
    events = {"INFO": 0, "WARNING": 0, "ERROR": 0}

    failed_by_user = {}
    failed_by_ip = {}
    error_messages = {}
    ip_counts = {}

    failed_logins = 0
    
    for line in lines:
        ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
        if ip_match:
            ip_address = ip_match.group()
            if is_valid_ip(ip_address):
                if ip_address in ip_counts:
                    ip_counts[ip_address] += 1
                else:
                    ip_counts[ip_address] = 1
        parts = line.split()
        event_type = parts[2]
        if event_type in events:
            events[event_type] += 1
        username_match = re.search(r"for user (\w+) from", line)
        if "Login failed" in line and username_match and ip_match:
            username = username_match.group(1)
            ip_address = ip_match.group()

            if is_valid_ip(ip_address):
                failed_logins += 1

            # Count failed logins by user

            if username in failed_by_user:
                failed_by_user[username] += 1
            else:
                failed_by_user[username] = 1

            # Count failed logins by IP

            if ip_address in failed_by_ip:
                failed_by_ip[ip_address] += 1
            else:
                failed_by_ip[ip_address] = 1

        if event_type == "ERROR":

            if "Login failed" in line:
                message = "Login failed"
            else:
                message = " ".join(parts[3:])

            if message in error_messages:
                error_messages[message] += 1
            else:
                error_messages[message] = 1
    return (
        events,
        failed_logins,
        failed_by_user,
        failed_by_ip,
        error_messages,
        ip_counts
    )            