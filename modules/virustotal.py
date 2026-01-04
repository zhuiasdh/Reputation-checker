import requests
import json

def check_virustotal(ip_address, api_key):
    """
    Queries VirusTotal API v3 for IP reputation.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status() # Check for HTTP errors
        
        data = response.json()
        
        # Extracting the "Malicious" count from the analysis stats
        stats = data['data']['attributes']['last_analysis_stats']
        malicious_count = stats['malicious']
        suspicious_count = stats['suspicious']
        
        return {
            "source": "VirusTotal",
            "ip": ip_address,
            "malicious_votes": malicious_count,
            "suspicious_votes": suspicious_count,
            "status": "Success"
        }

    except requests.exceptions.HTTPError as err:
        return {"source": "VirusTotal", "error": f"HTTP Error: {err}", "status": "Failed"}
    except Exception as e:
        return {"source": "VirusTotal", "error": f"Error: {e}", "status": "Failed"}