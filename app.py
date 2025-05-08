import streamlit as st
from link_scanner import scan_url
from text_analyzer import analyze_text

# Set page configuration for better presentation
st.set_page_config(page_title="OSINT Sentinel+", page_icon="🔍", layout="wide")

# Custom CSS for styling
st.markdown("""
    <style>
    .main-title {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .subtitle {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        font-weight: bold;
        color: #2c3e50;
        margin-top: 2rem;
    }
    .footer {
        text-align: center;
        margin-top: 3rem;
        color: #888;
        font-size: 0.9rem;
    }
    </style>
""", unsafe_allow_html=True)

# Header
st.markdown('<p class="main-title">OSINT Sentinel+ 🔍</p>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">A Rapid Scam Detection Tool for URLs and Text</p>', unsafe_allow_html=True)

# Layout using columns
col1, col2 = st.columns([1, 1])

# URL Scanner Section
with col1:
    st.markdown('<p class="section-header">URL Scanner</p>', unsafe_allow_html=True)
    st.markdown("Enter a website URL below (not an email address).")
    url_input = st.text_input("Enter a URL to scan (e.g., https://example.com):", key="url_input")
    scan_button = st.button("Scan URL")

    if scan_button:
        st.markdown('<p class="section-header">Scan Results (URL)</p>', unsafe_allow_html=True)
        if not url_input:
            st.markdown("<p style='color:red'>Error: Please enter a URL.</p>", unsafe_allow_html=True)
        elif "@" in url_input and not (url_input.startswith("http://") or url_input.startswith("https://")):
            st.markdown("<p style='color:red'>Error: This looks like an email address. Please enter a URL starting with http:// or https://.</p>", unsafe_allow_html=True)
        else:
            result, debug_info = scan_url(url_input)
            color = "green" if "Safe" in result else "yellow" if "Suspicious" in result or "Analysis not complete" in result else "red"
            st.markdown(f"<p style='color:{color}'>{result}</p>", unsafe_allow_html=True)
            with st.expander("Debug Info (URL)"):
                st.write(debug_info)

# Text Analysis Section
with col2:
    st.markdown('<p class="section-header">Text Analysis</p>', unsafe_allow_html=True)
    st.markdown("Enter text below to analyze for potential scams or phishing.")
    text_input = st.text_area("Enter text to analyze (e.g., a suspicious message or email):", key="text_input")
    analyze_button = st.button("Analyze Text")

    if analyze_button:
        st.markdown('<p class="section-header">Analysis Results (Text)</p>', unsafe_allow_html=True)
        if not text_input:
            st.markdown("<p style='color:red'>Error: Please enter some text to analyze.</p>", unsafe_allow_html=True)
        else:
            try:
                result, debug_info = analyze_text(text_input)
                color = "green" if "Safe" in result else "yellow" if "Suspicious" in result else "red"
                st.markdown(f"<p style='color:{color}'>{result}</p>", unsafe_allow_html=True)
                with st.expander("Debug Info (Text)"):
                    st.write(debug_info)
            except Exception as e:
                st.markdown(f"<p style='color:red'>Error: Unable to analyze text. {str(e)}</p>", unsafe_allow_html=True)
                with st.expander("Debug Info (Text)"):
                    st.write(f"Exception: {str(e)}")

# Instructions
st.markdown('<p class="section-header">How to Use</p>', unsafe_allow_html=True)
st.markdown("""
1. **URL Scanner**: Enter a URL (e.g., https://example.com) in the "URL Scanner" section. **Do not enter email addresses here.** Click "Scan URL" to check for malicious activity. *Note*: Uses VirusTotal API (free tier, 4 requests/minute limit).
2. **Text Analysis**: Enter a suspicious message or email in the "Text Analysis" section. Click "Analyze Text" to check for potential scams or phishing.
3. Results will display in green (safe), yellow (suspicious or pending), or red (error).
4. Check 'Debug Info' for more details if needed.
""")

# Footer
st.markdown('<p class="footer">Built by Team NextGen-Coders' #for Hackathon 2025'
'</p>', unsafe_allow_html=True)