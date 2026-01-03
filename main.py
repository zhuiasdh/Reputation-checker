import requests
import json
import argparse
import os  # <--- Needed to read the environment
from dotenv import load_dotenv  # <--- The new library

# --- 0. LOAD SECRETS ---
load_dotenv()  # This looks for the .env file and loads it
API_KEY = os.getenv('ABUSEIPDB_KEY')  # Grab the key by name

# Check if key loaded successfully
if not API_KEY:
    print("[!] Error: API Key not found. Did you create the .env file?")
    exit()

# --- 1. SETUP ARGUMENT PARSER ---
parser = argparse.ArgumentParser(description="CLI Tool to check IP Reputation via AbuseIPDB.")
parser.add_argument("ip", help="The IP address to scan.")
args = parser.parse_args()

# --- CONFIGURATION ---
IP_TO_CHECK = args.ip
url = 'https://api.abuseipdb.com/api/v2/check'
querystring = {
    'ipAddress': IP_TO_CHECK,
    'maxAgeInDays': '90'
}
headers = {
    'Accept': 'application/json',
    'Key': API_KEY
}

# --- EXECUTION ---
print(f"[*] Connecting to AbuseIPDB to scan: {IP_TO_CHECK}...")

response = requests.request(method='GET', url=url, headers=headers, params=querystring)

if response.status_code == 200:
    decoded_response = response.json()
    data = decoded_response['data']
    
    confidence_score = data['abuseConfidenceScore']
    isp = data['isp']
    country = data['countryCode']

    # --- RENDER HUD ---
    print("\n" + "="*40)
    print(f"   REPUTATION REPORT: {IP_TO_CHECK}")
    print("="*40)
    print(f" [!] Abuse Confidence Score: {confidence_score}%")
    print(f" [i] ISP:                    {isp}")
    print(f" [i] Country Code:           {country}")
    print("="*40 + "\n")

else:
    print(f"[!] Error: Mission Failed. Status Code: {response.status_code}")
    print(f"[!] Server Message: {response.text}")