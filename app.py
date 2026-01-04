import streamlit as st
import os
from dotenv import load_dotenv

# Import modules
from modules.abuseipdb import check_abuseipdb
from modules.virustotal import check_virustotal
from modules.urlscan import scan_url
from modules.shodan import get_shodan_info

# Load environment
load_dotenv()

# --- CONFIGURATION & THEME ---
st.set_page_config(
    page_title="Threat Intel Aggregator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Common Port Mapping for cleaner display
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-Alt"
}

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    /* Main Background and Text Color */
    .stApp {
        background-color: #FDFCF6; /* Light beige */
        color: #4A237F; /* Deep Purple */
    }
    
    /* Metrics Styling */
    [data-testid="stMetricValue"] {
        color: #4A237F !important;
        font-weight: 600;
    }
    [data-testid="stMetricLabel"] {
         color: #6c4e97 !important;
    }
    [data-testid="stMetricDelta"] svg {
        fill: #4A237F !important;
    }
    [data-testid="stMetricDelta"] > div {
        color: #4A237F !important;
    }

    /* Custom Purple Boxes */
    .purple-box {
        background-color: #5D3A9B;
        color: white !important; /* Force white text */
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        font-weight: 500;
        font-size: 16px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    
    /* Global Headers - The culprit from before */
    h1, h2, h3, h4 {
        color: #4A237F !important;
        font-weight: 700 !important;
    }
    
    /* Specific Override for the Banner Title to make it WHITE */
    .banner-title {
        color: white !important;
        margin: 0;
        font-size: 2rem;
        font-weight: 700;
    }
    
    /* Visuals Header */
    .visuals-header {
        font-size: 14px;
        color: #6c4e97;
        margin-bottom: 5px;
        font-weight: 600;
    }
    </style>
    """, unsafe_allow_html=True)


# --- SIDEBAR ---
with st.sidebar:
    st.title("⚙️ Settings")
    st.subheader("API Status")
    api_keys = {
        "AbuseIPDB": os.getenv("ABUSEIPDB_API_KEY"),
        "VirusTotal": os.getenv("VIRUSTOTAL_API_KEY"),
        "urlscan.io": os.getenv("URLSCAN_API_KEY"),
        "Shodan": os.getenv("SHODAN_API_KEY")
    }
    for service, key in api_keys.items():
        if key:
             st.markdown(f"✅ **{service}**: Active")
        else:
             st.markdown(f"❌ **{service}**: Missing")

# --- MAIN INTERFACE ---

st.markdown("""
<div style="background-color: #5D3A9B; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
    <h2 class="banner-title">🛡️ Threat Intelligence Dashboard</h2>
</div>
""", unsafe_allow_html=True)


# Input Area
col1, col2 = st.columns([3, 1])
with col1:
    target_ip = st.text_input("Enter Target IP", placeholder="e.g., 1.1.1.1 or 8.8.8.8")
with col2:
    st.write("")
    st.write("")
    scan_btn = st.button("🚀 Run Full Scan", type="primary", width="content")

# --- LOGIC ---
if scan_btn and target_ip:
    st.divider()
    
    # Initialize
    abuse_res, vt_res, urlscan_res, shodan_res = None, None, None, None

    # --- EXECUTE SCANS ---
    with st.spinner("🔄 Executing Cyber Kill Chain Scan..."):
        # 1. Reputation
        if api_keys["AbuseIPDB"]: abuse_res = check_abuseipdb(target_ip, api_keys["AbuseIPDB"])
        # 2. Malware
        if api_keys["VirusTotal"]: vt_res = check_virustotal(target_ip, api_keys["VirusTotal"])
        # 3. Infrastructure
        if api_keys["Shodan"]: shodan_res = get_shodan_info(target_ip, api_keys["Shodan"])
        # 4. Visuals
        if api_keys["urlscan.io"]: urlscan_res = scan_url(target_ip, api_keys["urlscan.io"])

    # SUCCESS BANNER
    st.markdown('<div style="background-color: #d4edda; color: #155724; padding: 10px; border-radius: 5px; border-left: 5px solid #28a745;">✅ Scan Complete</div>', unsafe_allow_html=True)
    st.write("")

    # --- TABS ---
    tab1, tab2, tab3 = st.tabs(["📊 Executive Summary", "📸 Visual Forensics Details", "📝 Raw Intelligence"])

    # === TAB 1: EXECUTIVE SUMMARY ===
    with tab1:
        st.write("")
        # Row 1: The 4 Main Cards
        c1, c2, c3, c4 = st.columns(4)
        
        # Card 1: AbuseIPDB
        with c1:
            if abuse_res and abuse_res.get('status') == 'Success':
                score = abuse_res['confidence_score']
                st.metric("Abuse Confidence", f"{score}%", delta="High Risk" if score > 50 else "Safe")
            else: st.metric("AbuseIPDB", "N/A")

        # Card 2: VirusTotal
        with c2:
            if vt_res and vt_res.get('status') == 'Success':
                malicious = vt_res['malicious_votes']
                total = malicious + vt_res['suspicious_votes']
                st.metric("VirusTotal", malicious, delta=f"{total} Detections" if malicious > 0 else "Clean")
            else: st.metric("VirusTotal", "N/A")

        # Card 3: Shodan Ports
        with c3:
            if shodan_res and shodan_res.get('status') == 'Success':
                ports = len(shodan_res.get('ports', []))
                st.metric("Open Ports", ports, delta=f"{shodan_res.get('os', 'Unknown OS')}")
            else: st.metric("Shodan", "N/A")

        # Card 4: Visuals
        with c4:
            st.markdown('<div class="visuals-header">Visuals</div>', unsafe_allow_html=True)
            if urlscan_res and urlscan_res.get('status') == 'Success' and 'screenshot_saved_as' in urlscan_res:
                 st.image(urlscan_res['screenshot_saved_as'], width="content")
                 st.caption("Latest Scan")
            else:
                 st.metric("Visuals", "Not Acquired")

        st.divider()

        # Row 2: Infrastructure Details (Purple Boxes)
        st.subheader("🏗️ Infrastructure Details (Shodan)")
        
        if shodan_res and shodan_res.get('status') == 'Success':
            i1, i2, i3 = st.columns(3)
            # Using custom HTML for the solid purple boxes with WHITE text forced
            with i1: st.markdown(f'<div class="purple-box">ISP: {shodan_res.get("isp", "N/A")}</div>', unsafe_allow_html=True)
            with i2: st.markdown(f'<div class="purple-box">OS: {shodan_res.get("os", "N/A")}</div>', unsafe_allow_html=True)
            with i3: st.markdown(f'<div class="purple-box">Organization: {shodan_res.get("org", "N/A")}</div>', unsafe_allow_html=True)
            
            st.write("")
            st.write("**Open Ports Detected:**")
            # Cleaner Bulleted List
            ports_list = shodan_res.get('ports', [])
            if ports_list:
                for port in ports_list:
                    service = COMMON_PORTS.get(port, "")
                    st.markdown(f"- **{port}** {f'({service})' if service else ''}")
            else:
                st.write("No open ports detected by Shodan.")
        else:
            st.warning("Shodan data unavailable.")

    # === TAB 2: Visual Details ===
    with tab2:
        if urlscan_res and urlscan_res.get('status') == 'Success':
            st.markdown(f"**Page Title:** {urlscan_res.get('page_title')}")
            st.markdown(f"**Actual URL:** {urlscan_res.get('page_url')}")
            st.markdown(f"[View Full urlscan.io Report ↗]({urlscan_res.get('report_url')})")
            if 'screenshot_saved_as' in urlscan_res:
                 st.image(urlscan_res['screenshot_saved_as'], caption="Full Resolution Screenshot")
        else:
            st.warning("No visual evidence available.")

    # === TAB 3: JSON ===
    with tab3:
        st.json({"abuseipdb": abuse_res, "virustotal": vt_res, "shodan": shodan_res, "urlscan": urlscan_res})

elif not scan_btn:
    st.info("👋 Enter an IP address above to begin the investigation.")