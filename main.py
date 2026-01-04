import os
import argparse
from dotenv import load_dotenv
import json

# Import our custom modules
from modules.abuseipdb import check_abuseipdb
from modules.virustotal import check_virustotal

# Load environment variables
load_dotenv()

ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def main():
    # 1. Setup CLI Arguments
    parser = argparse.ArgumentParser(description="God Mode Threat Intel Scanner (Level 2)")
    parser.add_argument("ip", help="The IP address to scan")
    parser.add_argument("--save", action="store_true", help="Save results to a JSON file")
    
    args = parser.parse_args()
    target_ip = args.ip

    print(f"\n--- 🛡️  Scanning Target: {target_ip} ---\n")

    # 2. Run AbuseIPDB Scan
    if ABUSE_KEY:
        print(">> Querying AbuseIPDB...")
        abuse_result = check_abuseipdb(target_ip, ABUSE_KEY)
        if abuse_result['status'] == 'Success':
            print(f"   [+] Abuse Confidence Score: {abuse_result['confidence_score']}%")
        else:
            print(f"   [!] Error: {abuse_result.get('error')}")
    else:
        print("   [!] AbuseIPDB Key missing in .env")

    # 3. Run VirusTotal Scan
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

    # 4. Save to file (Optional)
    if args.save:
        report = {
            "target": target_ip,
            "abuseipdb": abuse_result,
            "virustotal": vt_result # Note: variables might be undefined if keys are missing; simple version for now
        }
        filename = f"report_{target_ip}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        print(f"💾 Report saved to {filename}")

if __name__ == "__main__":
    main()