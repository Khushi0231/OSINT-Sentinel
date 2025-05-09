import streamlit as st
from link_scanner import scan_url, clear_cache
from text_analyzer import analyze_text, analyze_email_header

# Set page configuration
st.set_page_config(page_title="OSINT Sentinel+", page_icon="🔍", layout="wide")

# Custom CSS for styling
st.markdown("""
    <style>
    .main-title {
        font-size: 3rem;
        font-weight: bold;
        color: #d32f2f;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .subtitle {
        font-size: 1.2rem;
        color: #555;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        font-weight: bold;
        color: #37474f;
        margin-top: 1.5rem;
    }
    .footer {
        text-align: center;
        margin-top: 3rem;
        color: #777;
        font-size: 0.9rem;
    }
    .stButton>button {
        background-color: #d32f2f;
        color: white;
        border-radius: 5px;
    }
    .stButton>button:hover {
        background-color: #b71c1c;
    }
    </style>
""", unsafe_allow_html=True)

# Welcome message
st.markdown('<p class="main-title">OSINT Sentinel+ 🔍</p>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">A Rapid Scam Detection Tool for URLs, Text, and Email Headers</p>', unsafe_allow_html=True)
st.markdown("Protect yourself from online threats with our URL Scanner, Text Analyzer, and Email Header Analyzer!")

# Sidebar for navigation
with st.sidebar:
    st.markdown("## OSINT Sentinel+")
    st.markdown("Navigate through the app:")
    page = st.radio("Go to", ["Home", "URL Scanner", "Text Analysis", "Email Header Analysis", "How to Use"])

# Page content based on sidebar selection
if page == "Home":
    st.markdown("Welcome to **OSINT Sentinel+**, a tool designed to protect you from online scams by analyzing URLs, text, and email headers for potential threats. Use the sidebar to navigate to the URL Scanner, Text Analysis, or Email Header Analysis features.")

elif page == "URL Scanner":
    st.markdown('<p class="section-header">URL Scanner</p>', unsafe_allow_html=True)
    st.markdown("Enter a website URL below (not an email address).")
    
    # Use session state to manage input persistence
    if 'url_input' not in st.session_state:
        st.session_state.url_input = ""
    
    url_input = st.text_input("Enter a URL to scan (e.g., https://example.com):", value=st.session_state.url_input, key="url_input_field")
    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        scan_button = st.button("Scan URL")
    with col2:
        clear_url_button = st.button("Clear")
    with col3:
        refresh_cache_button = st.button("Refresh Cache")

    if clear_url_button:
        st.session_state.url_input = ""

    if refresh_cache_button:
        result = clear_cache()
        if "Error" in result:
            st.error(result)
        else:
            st.success(result)

    if scan_button:
        st.markdown('<p class="section-header">Scan Results (URL)</p>', unsafe_allow_html=True)
        if not url_input:
            st.markdown("<p style='color:red'>Error: Please enter a URL.</p>", unsafe_allow_html=True)
        elif "@" in url_input and not (url_input.startswith("http://") or url_input.startswith("https://")):
            st.markdown("<p style='color:red'>Error: This looks like an email address. Please enter a URL starting with http:// or https://.</p>", unsafe_allow_html=True)
        else:
            with st.spinner("Scanning URL... Please wait."):
                result, debug_info = scan_url(url_input)
            color = "green" if "Safe" in result else "yellow" if "Suspicious" in result or "Analysis not complete" in result else "red"
            st.markdown(f"<p style='color:{color}'>{result}</p>", unsafe_allow_html=True)
            with st.expander("Debug Info (URL)"):
                st.write(debug_info)

elif page == "Text Analysis":
    st.markdown('<p class="section-header">Text Analysis</p>', unsafe_allow_html=True)
    st.markdown("Enter text below to analyze for potential scams or phishing.")
    
    # Use session state to manage input persistence
    if 'text_input' not in st.session_state:
        st.session_state.text_input = ""
    
    text_input = st.text_area("Enter text to analyze (e.g., a suspicious message or email):", value=st.session_state.text_input, key="text_input_field")
    col1, col2 = st.columns([1, 1])
    with col1:
        analyze_button = st.button("Analyze Text")
    with col2:
        clear_text_button = st.button("Clear")

    if clear_text_button:
        st.session_state.text_input = ""

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
                if "Suspicious" in result:
                    if st.button("Copy to Clipboard"):
                        st.markdown("<p style='color:blue'>Please manually copy the result above (Streamlit does not support direct clipboard access).</p>", unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f"<p style='color:red'>Error: Unable to analyze text. {str(e)}</p>", unsafe_allow_html=True)
                with st.expander("Debug Info (Text)"):
                    st.write(f"Exception: {str(e)}")

elif page == "Email Header Analysis":
    st.markdown('<p class="section-header">Email Header Analysis</p>', unsafe_allow_html=True)
    st.markdown("Paste an email header below to analyze for potential red flags.")
    
    # Use session state to manage input persistence
    if 'header_input' not in st.session_state:
        st.session_state.header_input = ""
    
    header_input = st.text_area("Paste email header here:", value=st.session_state.header_input, key="header_input_field")
    col1, col2 = st.columns([1, 1])
    with col1:
        analyze_header_button = st.button("Analyze Header")
    with col2:
        clear_header_button = st.button("Clear")

    if clear_header_button:
        st.session_state.header_input = ""

    if analyze_header_button:
        st.markdown('<p class="section-header">Analysis Results (Email Header)</p>', unsafe_allow_html=True)
        if not header_input:
            st.markdown("<p style='color:red'>Error: Please paste an email header to analyze.</p>", unsafe_allow_html=True)
        else:
            try:
                result, debug_info = analyze_email_header(header_input)
                color = "green" if "Safe" in result else "yellow" if "Suspicious" in result else "red"
                st.markdown(f"<p style='color:{color}'>{result}</p>", unsafe_allow_html=True)
                with st.expander("Debug Info (Email Header)"):
                    st.write(debug_info)
                if "Suspicious" in result:
                    if st.button("Copy to Clipboard"):
                        st.markdown("<p style='color:blue'>Please manually copy the result above (Streamlit does not support direct clipboard access).</p>", unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f"<p style='color:red'>Error: Unable to analyze email header. {str(e)}</p>", unsafe_allow_html=True)
                with st.expander("Debug Info (Email Header)"):
                    st.write(f"Exception: {str(e)}")

else:  # How to Use
    st.markdown('<p class="section-header">How to Use</p>', unsafe_allow_html=True)
    st.markdown("""
    1. **URL Scanner**: Navigate to the URL Scanner page. Enter a URL (e.g., https://example.com) and click "Scan URL" to check for malicious activity. Use "Refresh Cache" to clear cached results. *Note*: Uses VirusTotal API (free tier, 4 requests/minute limit).
    2. **Text Analysis**: Navigate to the Text Analysis page. Enter a suspicious message or email and click "Analyze Text" to check for potential scams or phishing using rule-based and AI-based methods.
    3. **Email Header Analysis**: Navigate to the Email Header Analysis page. Paste an email header and click "Analyze Header" to check for red flags like suspicious sender domains or failed authentication.
    4. Results will display in green (safe), yellow (suspicious or pending), or red (error).
    5. Check 'Debug Info' for more details if needed.
    6. Use the "Clear" button to reset inputs.
    """)

# Footer
st.markdown('<p class="footer">Built by Team NextGen-Coders</p>', unsafe_allow_html=True)