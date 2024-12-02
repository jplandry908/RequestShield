#!/usr/bin/env python

import configparser
import pathlib

# Definizione del path del file
path = pathlib.Path(__file__).parent.resolve()

# Creazione del file di configurazione
config_file = configparser.ConfigParser()

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

# RISK SCORING (compile)
config_file["SCORING"] = {
    "path_risk_weight": "1.0",
    "geo_risk_weight": "0.5",
    "abuse_ip_weight": "0.9",
    "request_volume_weight": "0.6"
}


# Scrittura del file di configurazione
config_filename = "config.ini"
with open(config_filename, "w") as configfileObj:
    config_file.write(configfileObj)

print(f"Config file '{config_filename}' created successfully.")

# Lettura e stampa del contenuto del file di configurazione
with open(config_filename, "r") as read_file:
    content = read_file.read()
    print(f"\nContent of the config file '{config_filename}':\n")
    print(content)
