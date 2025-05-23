import streamlit as st
import pandas as pd
from link_scanner import scan_url, clear_cache
from text_analyzer import analyze_text, analyze_email_header
import os

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
st.markdown('<p class="subtitle">A Rapid Scam Detection Tool for URLs, Text, Email Headers, and More</p>', unsafe_allow_html=True)
st.markdown("Protect yourself from online threats with our URL Scanner, Text Analyzer, Email Header Analyzer, URL Statistics, and Social Media Metadata Extraction!")

# Sidebar for navigation
with st.sidebar:
    st.markdown("## OSINT Sentinel+")
    st.markdown("Navigate through the app:")
    page = st.radio("Go to", ["Home", "URL Scanner", "Text Analysis", "Email Header Analysis", "URL Statistics (MATLAB)", "Social Media Metadata (MATLAB)", "How to Use"])

# Page content based on sidebar selection
if page == "Home":
    st.markdown("Welcome to **OSINT Sentinel+**, a tool designed to protect you from online scams by analyzing URLs, text, email headers, and more. Use the sidebar to navigate to our features, including advanced URL Statistics and Social Media Metadata Extraction powered by MATLAB!")

elif page == "URL Scanner":
    st.markdown('<p class="section-header">URL Scanner</p>', unsafe_allow_html=True)
    st.markdown("Enter a website URL below (not an email address).")
    
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
        else:
            try:
                with st.spinner("Scanning URL... Please wait."):
                    result, debug_info = scan_url(url_input)
                color = "green" if "Safe" in result else "yellow" if "Suspicious" in result or "Analysis not complete" in result else "red"
                st.markdown(f"<p style='color:{color}'>{result}</p>", unsafe_allow_html=True)
                with st.expander("Debug Info (URL)"):
                    st.write(debug_info)
            except Exception as e:
                st.markdown(f"<p style='color:red'>Error: Failed to scan URL. {str(e)}</p>", unsafe_allow_html=True)

elif page == "Text Analysis":
    st.markdown('<p class="section-header">Text Analysis</p>', unsafe_allow_html=True)
    st.markdown("Enter text below to analyze for potential scams or phishing.")
    
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

elif page == "URL Statistics (MATLAB)":
    st.markdown('<p class="section-header">URL Statistics (Powered by MATLAB)</p>', unsafe_allow_html=True)
    st.markdown("This section showcases statistical analysis of URL scan results using MATLAB for advanced numerical computing.")
    
    try:
        stats = pd.read_csv("url_stats.csv", header=None).iloc[0]
        mean_flags, std_flags, max_flags = stats
        st.write(f"**Average Malicious Flags Across URLs:** {mean_flags:.2f}")
        st.write(f"**Standard Deviation of Malicious Flags:** {std_flags:.2f}")
        st.write(f"**Maximum Malicious Flags Detected:** {int(max_flags)}")
        
        try:
            st.image("url_histogram.png", caption="Distribution of Malicious Flags in URL Scans")
        except FileNotFoundError:
            st.markdown("<p style='color:orange'>Histogram not available (plotting not supported in this environment).</p>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.markdown("<p style='color:red'>Error: URL statistics not found. Please ensure the MATLAB script has been run.</p>", unsafe_allow_html=True)
        st.markdown("To generate statistics, scan some URLs using the URL Scanner, save the results to `url_data.csv`, and run the `url_stats.m` script in MATLAB.")

elif page == "Social Media Metadata (MATLAB)":
    st.markdown('<p class="section-header">Social Media Metadata Extraction (Powered by MATLAB)</p>', unsafe_allow_html=True)
    st.markdown("Extract metadata like geolocation and timestamps from a social media image.")

    # Option to select a pre-loaded image or upload a new one
    image_option = st.selectbox("Choose an image to analyze:", ["Upload a new image", "Sample Image 1", "Sample Image 2"])

    if image_option == "Upload a new image":
        uploaded_file = st.file_uploader("Upload a social media image (JPG format)", type=["jpg", "jpeg"])
        if uploaded_file is not None:
            # Save the uploaded image
            with open("uploaded_image.jpg", "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Simulate processing (since MATLAB is offline)
            with st.spinner("Extracting metadata..."):
                # For the demo, we'll manually swap in the metadata
                st.session_state.current_image = "uploaded_image.jpg"
                st.session_state.metadata_file = "metadata.csv"  # Will be uploaded manually
    else:
        # Pre-loaded sample images
        image_name = "image1.jpg" if image_option == "Sample Image 1" else "image2.jpg"
        metadata_file = "metadata_image1.csv" if image_option == "Sample Image 1" else "metadata_image2.csv"
        st.session_state.current_image = image_name
        st.session_state.metadata_file = metadata_file

    # Display the image and metadata if available
    if "current_image" in st.session_state and os.path.exists(st.session_state.current_image):
        st.image(st.session_state.current_image, caption="Selected Image", width=300)

        if "metadata_file" in st.session_state and os.path.exists(st.session_state.metadata_file):
            try:
                metadata = pd.read_csv(st.session_state.metadata_file, header=None).iloc[0]
                date_time, device, gps_lat, gps_lon = metadata
                st.write(f"**Date/Time of Capture:** {date_time}")
                st.write(f"**Device Used:** {device}")
                st.write(f"**GPS Latitude:** {gps_lat}")
                st.write(f"**GPS Longitude:** {gps_lon}")
                if gps_lat != 'Not available' and gps_lon != 'Not available':
                    st.markdown(f"[View Location on Google Maps](https://www.google.com/maps?q={gps_lat},{gps_lon})")
            except Exception as e:
                st.markdown(f"<p style='color:red'>Error: Failed to read metadata. Please try again.</p>", unsafe_allow_html=True)
        else:
            st.markdown("<p style='color:orange'>Metadata extraction in progress... Please wait.</p>", unsafe_allow_html=True)
            # For the demo, you'll manually upload metadata.csv if a new image is uploaded

else:  # How to Use
    st.markdown('<p class="section-header">How to Use</p>', unsafe_allow_html=True)
    st.markdown("""
    1. **URL Scanner**: Navigate to the URL Scanner page. Enter a URL (e.g., https://example.com) and click "Scan URL" to check for malicious activity.
    2. **Text Analysis**: Navigate to the Text Analysis page. Enter a suspicious message or email and click "Analyze Text" to check for scams.
    3. **Email Header Analysis**: Navigate to the Email Header Analysis page. Paste an email header and click "Analyze Header" to check for red flags.
    4. **URL Statistics (MATLAB)**: View statistical analysis of URL scan results, powered by MATLAB.
    5. **Social Media Metadata (MATLAB)**: Select or upload a social media image to extract metadata like geolocation and timestamps.
    6. Results will display in green (safe), yellow (suspicious or pending), or red (error).
    7. Use the "Clear" button to reset inputs.
    """)

# Footer
st.markdown('<p class="footer">Built by Team NextGen-Coders</p>', unsafe_allow_html=True)