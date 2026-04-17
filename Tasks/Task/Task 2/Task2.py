# task2_siem.py

import re
import json
import sys
from collections import Counter


# ---------------------------------
# Check Command Line Argument
# ---------------------------------
if len(sys.argv) != 2:
    print("Usage: python task2_siem.py <threshold>")
    sys.exit()

try:
    threshold = int(sys.argv[1])
except:
    print("Threshold must be a number.")
    sys.exit()


# ---------------------------------
# Read Log File
# ---------------------------------
log_file = "auth.log"

try:
    with open(log_file, "r") as file:
        logs = file.readlines()
except FileNotFoundError:
    print("Log file not found.")
    sys.exit()


# ---------------------------------
# Extract Failed Login IP Addresses
# ---------------------------------
ip_list = []

for line in logs:
    if "Failed password" in line:

        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)

        if match:
            ip_list.append(match.group(1))


# ---------------------------------
# Count Attack Attempts
# ---------------------------------
ip_count = Counter(ip_list)

malicious_ips = []

for ip, count in ip_count.items():

    if count >= threshold:
        malicious_ips.append({
            "ip_address": ip,
            "failed_attempts": count,
            "status": "Blocked"
        })


# ---------------------------------
# Save Output to JSON
# ---------------------------------
with open("blocked_ips.json", "w") as file:
    json.dump(malicious_ips, file, indent=4)


# ---------------------------------
# Display Results
# ---------------------------------
print("\n===== SIEM Lite Alert Report =====")

if len(malicious_ips) == 0:
    print("No suspicious IP addresses found.")

else:
    for item in malicious_ips:
        print("IP:", item["ip_address"])
        print("Failed Attempts:", item["failed_attempts"])
        print("Status:", item["status"])
        print("------------------------")

print("Results exported to blocked_ips.json")