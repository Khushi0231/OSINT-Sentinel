# Temporarily disabled due to lack of free API access
"""
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
INTELX_API_KEY = os.getenv("INTELX_API_KEY")

def check_breach(email):
    if not email or "@" not in email:
        return "Error: Invalid email address."

    url = "https://public.intelx.io/search"
    headers = {"x-key": INTELX_API_KEY}
    params = {"term": email, "maxresults": 10}

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            results = response.json().get("results", [])
            if results:
                return f"⚠️ Breached! Found in {len(results)} sources."
            return "✅ Safe: No breaches found."
        return f"Error: API returned status code {response.status_code}."
    except requests.exceptions.RequestException as e:
        return f"Error: Unable to connect to IntelX API. {str(e)}"

# Test the function
if __name__ == "__main__":
    test_email = "test@example.com"
    print(f"Checking email: {test_email}")
    result = check_breach(test_email)
    print(result)
"""

def check_breach(email):
    return "Feature disabled: No free breach checking API available."