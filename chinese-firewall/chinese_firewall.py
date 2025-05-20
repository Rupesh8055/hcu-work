import requests
import socket
import time
from urllib.parse import urlparse
import json # Keep this import as you'll use json.dumps

def check_accessibility(url, timeout=10):
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    results = {
        "url": url,
        "accessible": False,
        "status_code": None,
        "error": None,
        "ip_address": None,
        "response_time_ms": None,
        "reason": "Unknown",
        "check_location": "Current Server Location "
    }

    # Basic domain validation before attempting DNS or HTTP
    if not domain:
         results["error"] = "Invalid URL format: Could not extract domain."
         results["reason"] = "Invalid URL"
         return results

    try:
       
        try:
            # Attempt to resolve the IP address of the domain
            # This might reveal DNS blocking/poisoning if run from China
            results["ip_address"] = socket.gethostbyname(domain)
        except socket.gaierror:
            results["error"] = f"DNS resolution failed for the domain: {domain}."
            results["reason"] = "DNS Resolution Failure"
            return results

        start_time = time.time()
        # Add a check to ensure the URL has a scheme for requests.get
        if not parsed_url.scheme:
             url = "http://" + url # Default to http if no scheme

        response = requests.get(url, timeout=timeout, allow_redirects=True)
        end_time = time.time()

        results["response_time_ms"] = round((end_time - start_time) * 1000, 2)
        results["status_code"] = response.status_code

        if 200 <= response.status_code < 400:
            results["accessible"] = True
            results["reason"] = "Successfully connected and received a valid response."
        else:
            results["reason"] = f"Received HTTP status code: {response.status_code}"

    except requests.exceptions.ConnectionError:
        results["error"] = "Connection failed (e.g., host unreachable, IP blocked)."
        results["reason"] = "Connection Error (Possible IP blocking or firewall)"
    except requests.exceptions.Timeout:
        results["error"] = f"Request timed out after {timeout} seconds."
        results["reason"] = "Timeout (Possible connection throttling or blocking)"
    except requests.exceptions.TooManyRedirects:
        results["error"] = "Too many redirects."
        results["reason"] = "Redirect Loop"
    except requests.exceptions.RequestException as e:
        results["error"] = f"An unexpected request error occurred: {e}"
        results["reason"] = "Request Error"
    except Exception as e:
        results["error"] = f"An unexpected error occurred: {e}"
        results["reason"] = "General Error"

    return results




user_url = input("Enter the website URL you want to check: ")

accessibility_results = check_accessibility(user_url)


print("\n--- Accessibility Check Results ---")
print(json.dumps(accessibility_results, indent=2))

