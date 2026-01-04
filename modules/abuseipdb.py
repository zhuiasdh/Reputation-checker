import requests

def check_abuseipdb(ip_address, api_key):
    """
    Queries AbuseIPDB for IP reputation.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.request("GET", url, headers=headers, params=querystring)
        response.raise_for_status()
        
        decoded_response = response.json()
        confidence_score = decoded_response['data']['abuseConfidenceScore']
        
        return {
            "source": "AbuseIPDB",
            "ip": ip_address,
            "confidence_score": confidence_score,
            "status": "Success"
        }
        
    except requests.exceptions.HTTPError as err:
        return {"source": "AbuseIPDB", "error": f"HTTP Error: {err}", "status": "Failed"}
    except Exception as e:
        return {"source": "AbuseIPDB", "error": f"Error: {e}", "status": "Failed"}