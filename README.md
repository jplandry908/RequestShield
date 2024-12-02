# RequestShield 


**RequestShield** is a 100% Free and OpenSource tool designed to analyze HTTP access.logs and identify suspicious HTTP requests and potential security threats. It uses factors like geolocation, abuse history, request volume, and suspicious request paths to assign a risk score to each IP, providing actionable insights for security monitoring.


## Purpose

RequestShield helps security teams detect and mitigate threats by analyzing access logs in real-time. It's ideal for:
- **Intrusion detection** (unauthorized access attempts)
- **Rate limiting** (detecting DoS/DDoS traffic)
- **Abuse monitoring** (identifying flagged IPs)

## Features
- **Log Parsing:** Analyzes common log format access logs (https://en.wikipedia.org/wiki/Common_Log_Format).
- **Risk Scoring:** Factors considered include:
  - **Geolocation:** Risky countries (e.g., CN, RU, IN)
  - **Abuse History:** Checks IPs against AbuseIPDB
  - **Request Volume:** Flags high request rates
  - **Suspicious Paths:** Detects risky request paths (e.g., `/admin`)
- **HTML Report:** Generates a detailed report summarizing risks and anomalies.

## Setup

1. **Install dependencies**: 
   - Automatically managed on run (e.g., `requests`, `geoip2`, `abuseipdb`).
   
2. **Configure**: Edit `config.ini` to set:
   - Log file path
   - GeoIP DB path
   - AbuseIPDB API key
   - Request volume thresholds
## Usage

Run the tool with:

python3 requestshield.py

It processes the logs and generates a report (RequestShield_Report.html) summarizing suspicious activity and risks.
Output

- Risk Scoring: Each IP gets a score based on various risk factors.
- Report: HTML report with a summary of flagged IPs and anomalies.
