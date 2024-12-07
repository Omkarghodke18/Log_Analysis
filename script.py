import re # used for parsing log file with regular expression
import csv
from collections import defaultdict # Helps in counting occurrences without checking if a key exists first.


# File path
log_file = "sample.log"
output_file = "log_analysis_results.csv"


# Threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 5 # Number of failed login attempts needed to mark an IP as suspicious


# Data containers
ip_requests = defaultdict(int)
endpoint_counts = defaultdict(int)
failed_logins = defaultdict(int)


# Parse the log file
with open(log_file, 'r') as file:
    for line in file:   # Using regular expression for extracting data
        match = re.match(r'(\d+\.\d+\.\d+\.\d+) .*? "(?:POST|GET) (.*?) HTTP/.*?" (\d+) .*', line)
        if match:
            ip, endpoint, status_code = match.groups()
            ip_requests[ip] += 1
            endpoint_counts[endpoint] += 1
            
            # Check for failed login attempts
            if endpoint == '/login' and status_code == '401':
                failed_logins[ip] += 1



# Identify the most accessed endpoint
most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get)
most_accessed_count = endpoint_counts[most_accessed_endpoint]



# Detecting suspicious activity
suspicious_ips = {ip: count for ip, count in failed_logins.items() if count >= FAILED_LOGIN_THRESHOLD}
# Using dictionary comprehension to filter IPs with failed login counts exceeding the threshold (5)


                       # **Displaying result in well format**

# Displaying results
print("Requests per IP Address:")
for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip:<18} {count}")

print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

if suspicious_ips:
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<18} {count}")
else:
    print("\nNo Suspicious Activity Detected")


                           # **Code for saving result in CSV file in well format**
    
# Saving results to CSV in the expected format
with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)

    # Section 1: Requests per IP
    writer.writerow(["Requests per IP Address"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        writer.writerow([ip, count])

    writer.writerow([])

    # Section 2: Most Accessed Endpoint
    writer.writerow(["Most Frequently Accessed Endpoint"])
    writer.writerow([most_accessed_endpoint])
    writer.writerow([f"Accessed {most_accessed_count} times"])

    writer.writerow([])

    # Section 3: Suspicious Activity
    writer.writerow(["Suspicious Activity Detected"])
    if suspicious_ips:
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])
    else:
        writer.writerow(["No Suspicious Activity Detected"])

print(f"\nResults saved to {output_file}")


                          # **End Of Script**

"""
                    **Assignment of VRV Security**

Onkar Ghodke 
omkarghodke1092003@gmail.com
91+9022189874
Pune,Maharashtra,India

"""