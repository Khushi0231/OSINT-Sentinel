import re

def analyze_text(text):
    """
    Analyze text for potential scam or phishing content using rule-based keyword detection.
    Args:
        text (str): The text to analyze.
    Returns:
        tuple: (result message, debug info)
    """
    if not text:
        return "Error: Please enter some text to analyze.", "No text provided."

    # Rule-based check for common scam keywords
    scam_keywords = [
        "win", "winner", "prize", "claim", "click here", "urgent", "free money",
        "lottery", "inheritance", "million dollars", "verify your account",
        "password reset", "account suspended", "limited time offer"
    ]
    text_lower = text.lower()
    keyword_matches = [keyword for keyword in scam_keywords if keyword in text_lower]
    rule_based_result = "Suspicious" if keyword_matches else "Safe"
    debug_info = f"Rule-based check: {rule_based_result}, Matched keywords: {keyword_matches if keyword_matches else 'None'}"

    if rule_based_result == "Suspicious":
        return "⚠️ Suspicious: This text may be a scam or phishing attempt.", debug_info
    return "✅ Safe: No suspicious content detected.", debug_info

# Test the function
if __name__ == "__main__":
    test_text = "Congratulations! You've won $1,000,000! Click here to claim your prize now!"
    print(f"Analyzing text: {test_text}")
    result, debug = analyze_text(test_text)
    print(result)
    print(debug)