import re
from transformers import pipeline

# Load a pre-trained sentiment analysis model with error handling
try:
    sentiment_analyzer = pipeline("sentiment-analysis")
except Exception as e:
    sentiment_analyzer = None
    print(f"Warning: Failed to load sentiment analysis model. Error: {str(e)}")

def analyze_text(text):
    """
    Analyze text for potential scam or phishing content using both rule-based and AI-based detection.
    Args:
        text (str): The text to analyze.
    Returns:
        tuple: (result message, debug info)
    """
    if not text:
        return "Error: Please enter some text to analyze.", "No text provided."

    # Rule-based analysis: Check for scam keywords
    scam_keywords = [
        "win", "winner", "prize", "claim", "click here", "urgent", "free money",
        "lottery", "inheritance", "million dollars", "verify your account",
        "password reset", "account suspended", "limited time offer", "you've been selected",
        "act now", "exclusive offer", "bank alert", "payment required", "update your details",
        "security alert", "confirm your identity", "risk free", "immediate action"
    ]
    text_lower = text.lower()
    keyword_matches = [keyword for keyword in scam_keywords if keyword in text_lower]
    rule_based_result = "Suspicious" if keyword_matches else "Safe"
    rule_based_debug = f"Rule-based check: {rule_based_result}, Matched keywords: {keyword_matches if keyword_matches else 'None'}"

    # AI-based analysis: Sentiment analysis
    ai_debug = "AI Sentiment: Not available (model failed to load)"
    sentiment_label = "Unknown"
    sentiment_score = 0.0
    if sentiment_analyzer:
        try:
            sentiment_result = sentiment_analyzer(text)[0]
            sentiment_label = sentiment_result['label']  # e.g., "NEGATIVE", "POSITIVE"
            sentiment_score = sentiment_result['score']  # Confidence score
            ai_debug = f"AI Sentiment: {sentiment_label} (Confidence: {sentiment_score:.2f})"
        except Exception as e:
            ai_debug = f"AI Sentiment: Failed (Error: {str(e)})"

    # Combine results: Suspicious if rule-based OR negative sentiment with high confidence
    combined_suspicious = (rule_based_result == "Suspicious") or (sentiment_label == "NEGATIVE" and sentiment_score > 0.7)
    result = "⚠️ Suspicious: This text may be a scam or phishing attempt." if combined_suspicious else "✅ Safe: No suspicious content detected."
    debug_info = f"{rule_based_debug} | {ai_debug}"

    return result, debug_info

def analyze_email_header(header_text):
    """
    Analyze email headers for potential red flags.
    Args:
        header_text (str): The email header to analyze.
    Returns:
        tuple: (result message, debug info)
    """
    if not header_text:
        return "Error: Please enter an email header to analyze.", "No header provided."

    red_flags = []
    header_text = header_text.lower()

    # Check for suspicious sender domains
    suspicious_domains = ["example.com", "unknownsender.net"]
    if "from:" in header_text:
        for domain in suspicious_domains:
            if domain in header_text:
                red_flags.append(f"Suspicious sender domain: {domain}")

    # Check for missing or failed authentication headers
    if "dkim: pass" not in header_text:
        red_flags.append("DKIM authentication missing or failed")
    if "spf: pass" not in header_text:
        red_flags.append("SPF authentication missing or failed")

    # Check for unusual routing (simplified)
    if "received:" in header_text:
        received_lines = [line for line in header_text.split("\n") if "received:" in line]
        if len(received_lines) > 5:  # Arbitrary threshold for unusual routing
            red_flags.append("Unusual number of hops in email routing")

    result = "⚠️ Suspicious: Potential issues detected in email header." if red_flags else "✅ Safe: No red flags detected in email header."
    debug_info = f"Red Flags: {red_flags if red_flags else 'None'}"

    return result, debug_info

# Test the functions
if __name__ == "__main__":
    # Test text analysis
    test_text = "Congratulations! You've won $1,000,000! Click here to claim your prize now!"
    print(f"Analyzing text: {test_text}")
    result, debug = analyze_text(test_text)
    print(result)
    print(debug)

    # Test email header analysis
    test_header = """
    Received: from mail.example.com (mail.example.com [192.168.1.1]) by mx.google.com
    From: user@example.com
    DKIM: fail
    SPF: fail
    """
    print(f"\nAnalyzing email header:\n{test_header}")
    result, debug = analyze_email_header(test_header)
    print(result)
    print(debug)