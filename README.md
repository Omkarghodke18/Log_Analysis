# Log_Analysis                                           
                                                                        **ASSIGNMENT OF VRV SECURITY**

Log file analysis is a process of examining server log files to extract meaningful information about system performance, user behavior, and potential security issues. This project focuses on analyzing a web server log file by parsing its content, extracting key details, and generating insights such as request counts, frequently accessed endpoints, and detection of suspicious activity like brute-force login attempts.

a. Data Parsing
Use regular expressions to extract IP addresses, endpoints, and HTTP status codes from each log entry.
b. Data Analysis
Request Counts: Count requests per IP address.
Most Accessed Endpoint: Identify the endpoint with the highest access count.
Suspicious Activity Detection: Detect potential brute-force login attempts based on repeated failed logins (401 Unauthorized status).
c. Report Generation
Print the analysis results to the console.
Save results in a well-formatted CSV file with clear sections:
Requests per IP Address
Most Accessed Endpoint
Suspicious Activity Detected.
