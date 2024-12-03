import re
import csv
from collections import defaultdict

# Configurable threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parse the log file and return structured data."""
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    """Count the number of requests per IP address."""
    ip_request_counts = defaultdict(int)
    for log in logs:
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip_request_counts[match.group(1)] += 1
    sorted_ip_counts = sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_ip_counts

def identify_most_accessed_endpoint(logs):
    """Identify the most frequently accessed endpoint."""
    endpoint_counts = defaultdict(int)
    for log in logs:
        match = re.search(r'"[A-Z]+\s(/[^ ]*)', log)
        if match:
            endpoint_counts[match.group(1)] += 1
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    return most_accessed

def detect_suspicious_activity(logs):
    """Detect suspicious activity based on failed login attempts."""
    failed_login_attempts = defaultdict(int)
    for log in logs:
        if '401' in log or 'Invalid credentials' in log:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                failed_login_attempts[match.group(1)] += 1
    flagged_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}
    return flagged_ips

def save_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, output_file):
    """Save the analysis results to a CSV file."""
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Write Requests per IP section
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_counts)
        writer.writerow([])  # Blank line for separation

        # Write Most Accessed Endpoint section
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])  # Blank line for separation

        # Write Suspicious Activity section
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    # Load and process the log file
    log_file = 'sample.log'
    logs = parse_log_file(log_file)

    # Perform analysis
    ip_counts = count_requests_per_ip(logs)
    most_accessed_endpoint = identify_most_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    # Display results in terminal
    print("IP Address:         Request Count")
    for ip, count in ip_counts:
        print(f"{ip:<20}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    output_file = 'log_analysis_results.csv'
    save_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
