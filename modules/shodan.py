import requests

def get_shodan_info(ip, api_key):
    """
    Queries Shodan API for host information (Ports, OS, ISP).
    """
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    
    try:
        response = requests.get(url)
        
        # Shodan returns 404 if the IP has never been scanned by them
        if response.status_code == 404:
            return {
                "source": "Shodan", 
                "error": "IP not found in Shodan Database", 
                "status": "Skipped"
            }
            
        response.raise_for_status()
        data = response.json()
        
        return {
            "source": "Shodan",
            "os": data.get('os', 'Unknown'),
            "ports": data.get('ports', []),
            "isp": data.get('isp', 'Unknown'),
            "org": data.get('org', 'Unknown'),
            "hostnames": data.get('hostnames', []),
            "status": "Success"
        }

    except Exception as e:
        return {"source": "Shodan", "error": f"Error: {e}", "status": "Failed"}