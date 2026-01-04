import os
import argparse
from dotenv import load_dotenv
import json

# --- 1. IMPORTS FIXED ---
from modules.abuseipdb import check_abuseipdb
from modules.virustotal import check_virustotal
from modules.urlscan import scan_url  
from modules.shodan import get_shodan_info  

# Load environment variables
load_dotenv()

ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY") 
SHODAN_KEY = os.getenv("SHODAN_API_KEY")

def main():
    # Initialize variables to None so the script doesn't crash if we skip a step
    abuse_result = None
    vt_result = None
    urlscan_result = None

    # Setup CLI Arguments
    parser = argparse.ArgumentParser(description="God Mode Threat Intel Scanner (Level 3)")
    parser.add_argument("ip", help="The IP address to scan")
    parser.add_argument("--save", action="store_true", help="Save results to a JSON file")
    
    args = parser.parse_args()
    target_ip = args.ip

    print(f"\n--- 🛡️  Scanning Target: {target_ip} ---\n")

    # --- RUN ABUSEIPDB ---
    if ABUSE_KEY:
        print(">> Querying AbuseIPDB...")
        abuse_result = check_abuseipdb(target_ip, ABUSE_KEY)
        if abuse_result['status'] == 'Success':
            print(f"   [+] Abuse Confidence Score: {abuse_result['confidence_score']}%")
        else:
            print(f"   [!] Error: {abuse_result.get('error')}")
    else:
        print("   [!] AbuseIPDB Key missing in .env")

    # --- RUN VIRUSTOTAL ---
    if VT_KEY:
        print("\n>> Querying VirusTotal...")
        vt_result = check_virustotal(target_ip, VT_KEY)
        if vt_result['status'] == 'Success':
            print(f"   [+] Malicious Votes: {vt_result['malicious_votes']}")
            print(f"   [+] Suspicious Votes: {vt_result['suspicious_votes']}")
        else:
            print(f"   [!] Error: {vt_result.get('error')}")
    else:
        print("   [!] VirusTotal Key missing in .env")

    print("\n---------------------------------------")

    # --- RUN URLSCAN.IO ---
    if URLSCAN_KEY:
        print("\n>> Launching urlscan.io Scanner...")
        urlscan_result = scan_url(target_ip, URLSCAN_KEY)
        
        if urlscan_result['status'] == 'Success':
            print(f"   [+] Report Link: {urlscan_result['report_url']}")
            print(f"   [+] Page Title:  {urlscan_result['page_title']}")
            print(f"   [+] Actual URL:  {urlscan_result['page_url']}")
            print(f"   [📸] Screenshot:  {urlscan_result['screenshot_saved_as']}")
        else:
            print(f"   [!] Error: {urlscan_result.get('error')}")
    else:
        print("   [!] urlscan.io Key missing in .env")

    # --- RUN SHODAN ---
    shodan_result = None # Initialize
    if SHODAN_KEY:
        print("\n>> Querying Shodan (Infrastructure)...")
        shodan_result = get_shodan_info(target_ip, SHODAN_KEY)
        
        if shodan_result['status'] == 'Success':
            print(f"   [+] OS: {shodan_result['os']}")
            print(f"   [+] ISP: {shodan_result['isp']}")
            print(f"   [+] Open Ports: {shodan_result['ports']}")
        else:
            print(f"   [!] Status: {shodan_result.get('error')}")
    else:
        print("   [!] Shodan Key missing")
        
    # --- SAVE REPORT ---
    if args.save:
        report = {
            "target": target_ip,
            "abuseipdb": abuse_result,
            "virustotal": vt_result,
            "urlscan": urlscan_result,
            "shodan": shodan_result
        }
        filename = f"report_{target_ip}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        print(f"\n💾 Report saved to {filename}")

if __name__ == "__main__":
    main()