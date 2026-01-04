import requests
import time
import os

def scan_url(target, api_key, output_folder="."):
    """
    Submits a scan, waits for results, extracts metadata (Title/URL),
    and downloads the screenshot.
    """
    scan_url = "https://urlscan.io/api/v1/scan/"
    
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    data = {
        "url": target,
        "visibility": "public"
    }

    try:
        # 1. Submit the Scan
        print("   [~] Submitting scan request...")
        response = requests.post(scan_url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        
        uuid = result.get('uuid')
        result_api_url = result.get('api') 
        
        print(f"   [~] Scan UUID: {uuid}")
        print("   [~] Waiting for results (approx 10-30s)...")

        # 2. Poll for Results
        max_retries = 20 
        for i in range(max_retries):
            time.sleep(5) 
            
            check_response = requests.get(result_api_url)
            
            if check_response.status_code == 200:
                scan_data = check_response.json()
                
                # --- NEW: Extract Metadata ---
                page_data = scan_data.get('page', {})
                page_title = page_data.get('title', 'No Title Found')
                page_url = page_data.get('url', target)
                # -----------------------------

                # Get Screenshot URL
                screenshot_url = scan_data['task']['screenshotURL']
                
                print("   [+] Scan Finished. Downloading screenshot...")
                img_data = requests.get(screenshot_url).content
                
                safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
                filename = f"screenshot_{safe_target}.png"
                file_path = os.path.join(output_folder, filename)
                
                with open(file_path, 'wb') as handler:
                    handler.write(img_data)
                
                return {
                    "source": "urlscan.io",
                    "report_url": scan_data['task']['reportURL'],
                    "page_title": page_title,     # <--- Returned
                    "page_url": page_url,         # <--- Returned
                    "screenshot_saved_as": filename,
                    "status": "Success"
                }
                
            elif check_response.status_code == 404:
                print(f"       ... still scanning ({i+1}/{max_retries})")
                continue
            else:
                return {"source": "urlscan.io", "error": f"API Error: {check_response.status_code}", "status": "Failed"}

        return {"source": "urlscan.io", "error": "Timed out waiting for scan results", "status": "Failed"}

    except requests.exceptions.HTTPError as err:
        return {"source": "urlscan.io", "error": f"HTTP Error: {err}", "status": "Failed"}
    except Exception as e:
        return {"source": "urlscan.io", "error": f"Error: {e}", "status": "Failed"}