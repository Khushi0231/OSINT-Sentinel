import requests
import os
import json
import base64
from urllib.parse import quote
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def scan_url(url):
    """
    Scan a URL for malicious activity using the VirusTotal API with caching.
    Args:
        url (str): The URL to scan.
    Returns:
        tuple: (message, debug_info) - The result message and debug information.
    """
    if not url:
        return "Error: Please enter a URL.", "No URL provided."
    if not (url.startswith("http://") or url.startswith("https://")):
        return "Error: Invalid URL. Please enter a valid URL starting with http:// or https:// (e.g., https://example.com).", "Invalid URL format."

    # Load cache
    cache_file = "url_cache.json"
    cache = {}
    try:
        if not os.path.exists(cache_file):
            with open(cache_file, "w") as f:
                json.dump({}, f)
        with open(cache_file, "r") as f:
            cache = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        return "Error: Unable to load cache.", f"Cache error: {str(e)}"

    # Check cache
    if url in cache:
        result, debug_info = cache[url]
        debug_info += " (From cache)"
        return result, debug_info

    # Encode the URL for VirusTotal API
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        # Get scan results directly (VirusTotal API v3 requires a GET request for already scanned URLs)
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 404:
            # If URL not found, submit it for scanning
            vt_submit_url = "https://www.virustotal.com/api/v3/urls"
            payload = {"url": url}
            response = requests.post(vt_submit_url, headers=headers, data=payload)
            if response.status_code != 200:
                error_msg = f"Error: Unable to scan URL. Status code: {response.status_code}"
                if response.status_code == 429:
                    error_msg = "Error: VirusTotal API quota exceeded. Please use cached results or try again later."
                return error_msg, f"Submission failed: {response.text}"
            url_id = response.json()["data"]["id"]
            vt_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            response = requests.get(vt_url, headers=headers)

        if response.status_code != 200:
            return f"Error: Unable to retrieve scan results. Status code: {response.status_code}", f"Analysis retrieval failed: {response.text}"

        analysis = response.json()["data"]["attributes"]
        status = analysis.get("status", "completed")
        debug_info = f"Analysis status: {status}"

        if status == "completed":
            stats = analysis.get("stats", analysis.get("results", {}))
            debug_info += f", Stats: {stats}"
            malicious = stats.get("malicious", 0)
            result = f"⚠️ Suspicious: {malicious} security vendors flagged this URL." if malicious > 0 else "✅ Safe: No malicious activity detected."
            
            # Cache the result
            cache[url] = (result, debug_info)
            with open(cache_file, "w") as f:
                json.dump(cache, f)
            return result, debug_info
        else:
            return "⚠️ Analysis not complete. Please try again in a few seconds.", debug_info

    except requests.exceptions.RequestException as e:
        return f"Error: Unable to connect to VirusTotal API. {str(e)}", f"Connection error: {str(e)}"

def clear_cache():
    """
    Clear the URL cache.
    """
    cache_file = "url_cache.json"
    try:
        with open(cache_file, "w") as f:
            json.dump({}, f)
        return "Cache cleared successfully."
    except IOError as e:
        return f"Error: Unable to clear cache. {str(e)}"

# Test the function
if __name__ == "__main__":
    test_url = "https://example.com"
    print(f"Scanning URL: {test_url}")
    result, debug = scan_url(test_url)
    print(result)
    print(debug)