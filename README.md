# Log Analysis Script

This Python script analyzes web server log files to extract and analyze key information such as request counts per IP address, the most frequently accessed endpoint, and suspicious activity related to failed login attempts. It is designed to process large log files efficiently and provide insights into server traffic, making it a useful tool for cybersecurity-related programming tasks.

## Features

1. **Count Requests per IP Address**:
   - Extracts and counts the number of requests made by each IP address.
   - Sorts and displays the IP addresses with their respective request counts in descending order.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Extracts endpoint URLs or resource paths from log entries.
   - Identifies the most frequently accessed endpoint and provides the access count.

3. **Detect Suspicious Activity**:
   - Detects brute force login attempts based on failed login status (HTTP 401 or "Invalid credentials").
   - Flags IP addresses with failed login attempts exceeding a specified threshold (default: 10 attempts).

4. **Output Results**:
   - Displays results in the terminal.
   - Saves the analysis results to a CSV file (`log_analysis_results.csv`), with sections:
     - **Requests per IP**
     - **Most Accessed Endpoint**
     - **Suspicious Activity**
