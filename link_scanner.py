import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def scan_url(url):
    """
    Scan a URL for malicious activity using the VirusTotal API.
    Args:
        url (str): The URL to scan.
    Returns:
        tuple: (message, debug_info) - The result message and debug information.
    """
    if not url:
        return "Error: Please enter a URL.", "No URL provided."
    if not (url.startswith("http://") or url.startswith("https://")):
        return "Error: Invalid URL. Please enter a valid URL starting with http:// or https:// (e.g., https://example.com).", "Invalid URL format."

    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}

    try:
        # Submit URL for scanning
        payload = {"url": url}
        response = requests.post(vt_url, headers=headers, data=payload)
        if response.status_code != 200:
            return f"Error: Unable to scan URL. Status code: {response.status_code}", f"Submission failed: {response.text}"

        url_id = response.json()["data"]["id"]

        # Get scan results
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        response = requests.get(analysis_url, headers=headers)
        if response.status_code != 200:
            return f"Error: Unable to retrieve scan results. Status code: {response.status_code}", f"Analysis retrieval failed: {response.text}"

        analysis = response.json()["data"]["attributes"]
        status = analysis.get("status")
        debug_info = f"Analysis status: {status}"

        if status == "completed":
            stats = analysis["stats"]
            debug_info += f", Stats: {stats}"
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return f"⚠️ Suspicious: {malicious} security vendors flagged this URL.", debug_info
            return "✅ Safe: No malicious activity detected.", debug_info
        else:
            return "⚠️ Analysis not complete. Please try again in a few seconds.", debug_info

    except requests.exceptions.RequestException as e:
        return f"Error: Unable to connect to VirusTotal API. {str(e)}", f"Connection error: {str(e)}"

# Test the function
if __name__ == "__main__":
    test_url = "https://example.com"
    print(f"Scanning URL: {test_url}")
    result, debug = scan_url(test_url)
    print(result)
    print(debug)