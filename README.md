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
   - Automatically managed on first python3 requestshield.py run (e.g., `requests`, `geoip2`, `abuseipdb`).
     
2. **Obtain GeoLite2-Country.mmdb**
RequestShield use GeoLite2 database to geo-locate IP. 
- GeoLite2 databases are provided by MaxMind. You can download them from their website.
- You need an account to download the GeoLite2 databases.
- Download GeoLite2-Country Database.mmdb
- Place the GeoLite2-Country.mmdb File in main directory where requestshield.py is executed.
  
3. **ABUSEIPDB** 
RequestShield use ABUSEIPDB (https://www.abuseipdb.com/) API Key to assess IP abuse and related security threats.
- Create an Account: Go to AbuseIPDB and create a free or premium account.
- Generate API Key:
        Log in to your account.
        Navigate to API from the dashboard.
        Click Create Key and set permissions as needed.
- Copy the API Key: Save the key securely; you'll need it to configure RequestShield.

Use this API key in the config.py file under the [API] section to enable abuse database lookups.

4. **Configure**: Edit `config.py` to set:
   - Log file path
   - GeoIP DB path
   - AbuseIPDB API key
   - Request volume thresholds
  
```bash
# DEFAULT (compile)
config_file["DEFAULT"] = {
    "geoip_db": str(path / "GeoLite2-Country.mmdb"),
    "log_file": str(path / "./logs/access.log"),
    "max_requests_per_minute": int(changeme),
    "risky_country": str("changeme"),
    "unusual_status_codes": str("changeme")

}

# API (compile)
config_file["API"] = {
    "abuseipdb_api_key": "changeme"
}

# WHITELIST (compile)
config_file["WHITELIST"] = {
    "ips": "changeme"
}
```
Once properly edited, run:
```bash
python3 config.py
```
## Usage

Run the tool with:

python3 requestshield.py

It processes the logs and generates a report (RequestShield_Report.html) summarizing suspicious activity and risks.
Output

- Risk Scoring: Each IP gets a score based on various risk factors.
- Report: HTML report with a summary of flagged IPs and anomalies.
