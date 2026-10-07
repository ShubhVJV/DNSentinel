import sys
import os
import json
import socket

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import pandas as pd
from dnslib import DNSRecord

from common.config import SERVER_IP, SERVER_PORT, DNS_DOMAIN
from client.client import send_packet

RESULT_FILE = os.path.join(PROJECT_ROOT, "analysis", "last_transfer.json")
CLEAN_FILE = os.path.join(PROJECT_ROOT, "analysis", "metrics_clean.csv")
LOSS_FILE = os.path.join(PROJECT_ROOT, "analysis", "metrics_loss20.csv")


# ==========================================
# Page Configuration & Professional CSS
# ==========================================
st.set_page_config(
    page_title="DNSentinel Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif !important;
        background-color: #0e1117;
        color: #e0e0e0;
    }
    
    /* Status Indicator Dot */
    .status-dot {
        height: 12px;
        width: 12px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 10px;
        vertical-align: middle;
    }
    .status-dot.online { 
        background-color: #10b981; 
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.6); 
    }
    .status-dot.offline { 
        background-color: #ef4444; 
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.6); 
    }
    
    /* Custom Metric Cards */
    .custom-metric {
        background-color: #1a1d24;
        border: 1px solid #2b2f3a;
        border-radius: 6px;
        padding: 20px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        margin-bottom: 1rem;
    }
    .custom-metric-label {
        font-size: 0.75rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 8px;
        font-weight: 600;
    }
    .custom-metric-value {
        font-size: 1.75rem;
        font-weight: 600;
        color: #f8fafc;
        display: flex;
        align-items: center;
    }
    
    /* Section Headers */
    .section-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: #f8fafc;
        margin-top: 2rem;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid #2b2f3a;
    }
    
    /* Terminal Output Box */
    .terminal-box {
        background-color: #0f1115;
        border: 1px solid #2b2f3a;
        border-left: 4px solid #10b981;
        border-radius: 4px;
        padding: 16px;
        font-family: 'Courier New', Courier, monospace;
        color: #10b981;
        font-size: 0.95rem;
        white-space: pre-wrap;
        word-wrap: break-word;
    }
    
    /* Primary Button Override */
    .stButton>button {
        width: 100%;
        border-radius: 4px;
        font-weight: 600;
        letter-spacing: 0.5px;
        background-color: #3b82f6 !important;
        color: white !important;
        border: none !important;
        transition: all 0.2s;
    }
    .stButton>button:hover {
        background-color: #2563eb !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
    }
    /* ==========================================
   DNSentinel Hero Header
   ========================================== */

.hero-header {
    text-align: center;
    padding: 20px 0 10px 0;
    margin-bottom: 25px;
}

.hero-title {
    font-size: 3.2rem;
    font-weight: 800;
    letter-spacing: 1px;
    margin: 0;
    color: #f8fafc;
    text-shadow:
        0 0 10px rgba(59, 130, 246, 0.45),
        0 0 25px rgba(59, 130, 246, 0.20);
}

.hero-title .accent {
    color: #3b82f6;
}

.hero-subtitle {
    margin-top: 10px;
    font-size: 1.05rem;
    font-weight: 500;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #94a3b8;
}

.hero-line {
    width: 120px;
    height: 3px;
    margin: 18px auto 0 auto;
    border-radius: 10px;
    background: linear-gradient(
        90deg,
        #2563eb,
        #10b981
    );
    box-shadow: 0 0 12px rgba(59, 130, 246, 0.45);
}
    </style>
""", unsafe_allow_html=True)


# ==========================================
# Helper Function for Metric UI
# ==========================================
def render_metric_card(label, value, status=None):
    dot_html = ""
    if status == "online":
        dot_html = '<span class="status-dot online"></span>'
    elif status == "offline":
        dot_html = '<span class="status-dot offline"></span>'
        
    return f"""
    <div class="custom-metric">
        <div class="custom-metric-label">{label}</div>
        <div class="custom-metric-value">{dot_html}{value}</div>
    </div>
    """

# ==========================================
# Session State
# ==========================================
if "result" not in st.session_state:
    st.session_state.result = None

if "message" not in st.session_state:
    st.session_state.message = ""

if "transmission_history" not in st.session_state:
    st.session_state.transmission_history = []


# ==========================================
# Header
# ==========================================
st.markdown("<h2 style='margin-bottom: 0;'>DNSentinel Dashboard</h2>", unsafe_allow_html=True)
st.markdown("<p style='color: #94a3b8; font-size: 1rem;'>Adaptive Encrypted DNS Tunnel Telemetry & Threat Intelligence</p>", unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# Navigation
page = st.sidebar.radio("Navigation", ["Secure Tunnel", "Threat Detection (Live)"])

@st.cache_resource
def get_analyzer():
    from detection.analyzer import DNSAnalyzer
    analyzer = DNSAnalyzer()
    analyzer.start_sniffing()
    analyzer.simulate_traffic() # Fallback for demo
    return analyzer

def render_threat_detection():
    st.markdown('<div class="section-title">Live Threat Intelligence Dashboard</div>', unsafe_allow_html=True)
    analyzer = get_analyzer()
    
    col1, col2, col3, col4 = st.columns(4)
    col1.markdown(render_metric_card("Total Packets Analyzed", len(analyzer.packet_logs)), unsafe_allow_html=True)
    col2.markdown(render_metric_card("Active Alerts", len(analyzer.alerts), "offline" if len(analyzer.alerts)>0 else "online"), unsafe_allow_html=True)
    col3.markdown(render_metric_card("Unique IPs Tracked", len(analyzer.query_history)), unsafe_allow_html=True)
    col4.markdown(render_metric_card("Analysis Engine", "Running", "online" if analyzer.is_running else "offline"), unsafe_allow_html=True)
    
    auto_refresh = st.checkbox("Auto-Refresh (1s)", value=True)
    
    st.markdown("### Recent Alerts")
    if analyzer.alerts:
        alerts_df = pd.DataFrame(analyzer.alerts[::-1])
        st.dataframe(alerts_df.head(10), use_container_width=True)
    else:
        st.info("No threats detected yet.")
        
    st.markdown("### Live DNS Traffic Stream")
    if analyzer.packet_logs:
        logs_df = pd.DataFrame(analyzer.packet_logs[::-1])
        st.dataframe(logs_df.head(15), use_container_width=True)
    else:
        st.info("Listening for DNS packets...")
        
    if auto_refresh:
        import time
        time.sleep(1)
        st.rerun()

if page == "Threat Detection (Live)":
    render_threat_detection()
    st.stop()


# ==========================================
# Server Status Module
# ==========================================
def check_server_status():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        health_domain = f"health.{DNS_DOMAIN}"
        request = DNSRecord.question(health_domain, "A")
        sock.sendto(request.pack(), (SERVER_IP, SERVER_PORT))
        data, address = sock.recvfrom(4096)
        response = DNSRecord.parse(data)
        return response.header.rcode == 0
    except Exception as e:
        return False
    finally:
        sock.close()

server_online = check_server_status()
packets_sent = sum(item["Successful"] + item["Lost"] for item in st.session_state.transmission_history)

# Render Global Status Bar
col1, col2, col3 = st.columns(3)
with col1:
    status_state = "online" if server_online else "offline"
    status_text = "Server Online" if server_online else "Server Offline"
    st.markdown(render_metric_card("Infrastructure Status", status_text, status_state), unsafe_allow_html=True)
with col2:
    port_text = "8053 Active" if server_online else "8053 Inactive"
    st.markdown(render_metric_card("UDP Listener", port_text), unsafe_allow_html=True)
with col3:
    st.markdown(render_metric_card("Total Packets Dispatched", packets_sent), unsafe_allow_html=True)


# ==========================================
# Transmission Configuration
# ==========================================
st.markdown('<div class="section-title">Transmission Configuration</div>', unsafe_allow_html=True)

c1, c2, c3 = st.columns([1, 1, 2])
with c1:
    client_id = st.text_input("Client ID", value="C01")
with c2:
    session_id = st.text_input("Session ID", value="SESSION001")
with c3:
    loss_rate = st.slider("Simulated Drop Probability", min_value=0.0, max_value=0.5, value=0.0, step=0.05, format="%.2f")

message = st.text_area(
    "Data Payload",
    value="DNSentinel demonstration: encrypted data is fragmented, encoded into DNS queries, transmitted to the server, reassembled, and decrypted.",
    height=100
)

# ==========================================
# Send Button
# ==========================================
st.markdown("<br>", unsafe_allow_html=True)
send_button = st.button("Initiate Encrypted Transfer")

if send_button:
    if not message.strip():
        st.error("Payload cannot be empty.")
    elif not client_id.strip():
        st.error("Client ID is required.")
    elif not session_id.strip():
        st.error("Session ID is required.")
    else:
        if os.path.exists(RESULT_FILE):
            os.remove(RESULT_FILE)

        st.session_state.result = None
        st.session_state.message = ""

        with st.spinner("Modulating data through DNS infrastructure..."):
            result = send_packet(
                payload=message,
                client_id=client_id,
                session_id=session_id,
                loss_rate=loss_rate
            )

        st.session_state.result = result
        st.session_state.message = message

        if result["success"]:
            transmission = {
                "Transmission": len(st.session_state.transmission_history) + 1,
                "Client": client_id,
                "Session": session_id,
                "Fragments": result["fragments"],
                "Successful": result["successful_fragments"],
                "Lost": result["lost_fragments"],
                "Average RTT (ms)": result["average_rtt"],
                "Packet Loss (%)": result["packet_loss"],
                "Adaptive Delay (s)": result["adaptive_delay"]
            }
            st.session_state.transmission_history.append(transmission)


# ==========================================
# Current Transmission Result Dashboard
# ==========================================
if st.session_state.result is not None:
    result = st.session_state.result

    if result["success"]:
        st.markdown('<div class="section-title">Latest Transmission Report</div>', unsafe_allow_html=True)

        # Progress Overview
        total_frag = result["fragments"]
        completed = result["successful_fragments"] + result["lost_fragments"]
        progress_val = completed / total_frag if total_frag > 0 else 0
        st.progress(progress_val, text=f"Processing Execution: {completed} / {total_frag} blocks resolved")
        st.markdown("<br>", unsafe_allow_html=True)

        # Results Data Grid
        r1, r2, r3, r4 = st.columns(4)
        r1.markdown(render_metric_card("Total Fragments", result["fragments"]), unsafe_allow_html=True)
        r2.markdown(render_metric_card("Delivered", result["successful_fragments"]), unsafe_allow_html=True)
        r3.markdown(render_metric_card("Dropped", result["lost_fragments"]), unsafe_allow_html=True)
        r4.markdown(render_metric_card("Loss Ratio", f"{result['packet_loss']:.2f}%"), unsafe_allow_html=True)

        p1, p2, p3, p4 = st.columns(4)
        p1.markdown(render_metric_card("Min RTT", f"{result['minimum_rtt']:.3f} ms"), unsafe_allow_html=True)
        p2.markdown(render_metric_card("Avg RTT", f"{result['average_rtt']:.3f} ms"), unsafe_allow_html=True)
        p3.markdown(render_metric_card("Max RTT", f"{result['maximum_rtt']:.3f} ms"), unsafe_allow_html=True)
        p4.markdown(render_metric_card("Adaptive Delay", f"{result['adaptive_delay']:.3f} s"), unsafe_allow_html=True)

        # Reconstructed Payload Area
        st.markdown("<p style='font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; font-weight: 600; margin-top: 1rem; margin-bottom: 0.5rem;'>Server Payload Reconstruction</p>", unsafe_allow_html=True)
        
        if os.path.exists(RESULT_FILE):
            try:
                with open(RESULT_FILE, "r", encoding="utf-8") as file:
                    server_result = json.load(file)

                if (server_result.get("status") == "success" and
                    server_result.get("client_id") == client_id and
                    server_result.get("session_id") == session_id):
                    
                    st.markdown(f"""
                        <div class="terminal-box">
[Decryption Successful] Validating integrity... OK
[Data Buffer] -> {server_result.get('message', '')}
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    st.warning("Data mismatch detected in server response logs.")
            except Exception as e:
                st.error(f"Failed to read server trace: {e}")
        else:
            st.warning("Server trace file currently unavailable.")


# ==========================================
# Live Transmission Charts
# ==========================================
if st.session_state.transmission_history:
    st.markdown('<div class="section-title">Telemetry & Historical Analysis</div>', unsafe_allow_html=True)
    
    history = pd.DataFrame(st.session_state.transmission_history)

    ch1, ch2 = st.columns(2)
    with ch1:
        st.markdown("<p style='color: #cbd5e1; font-weight: 500;'>Average RTT (ms) Tracking</p>", unsafe_allow_html=True)
        st.line_chart(history[["Transmission", "Average RTT (ms)"]].set_index("Transmission"), use_container_width=True)

        st.markdown("<p style='color: #cbd5e1; font-weight: 500; margin-top: 1rem;'>Delivery Resolution</p>", unsafe_allow_html=True)
        st.bar_chart(history[["Transmission", "Successful", "Lost"]].set_index("Transmission"), use_container_width=True)

    with ch2:
        st.markdown("<p style='color: #cbd5e1; font-weight: 500;'>Packet Loss Tolerance (%)</p>", unsafe_allow_html=True)
        st.line_chart(history[["Transmission", "Packet Loss (%)"]].set_index("Transmission"), use_container_width=True)

        st.markdown("<p style='color: #cbd5e1; font-weight: 500; margin-top: 1rem;'>Adaptive Backoff Scaling (s)</p>", unsafe_allow_html=True)
        st.line_chart(history[["Transmission", "Adaptive Delay (s)"]].set_index("Transmission"), use_container_width=True)

    # History Table
    st.markdown("<p style='color: #cbd5e1; font-weight: 500; margin-top: 1rem;'>Session Log</p>", unsafe_allow_html=True)
    st.dataframe(history, use_container_width=True, hide_index=True)

    col_empty, col_btn = st.columns([5, 1])
    with col_btn:
        if st.button("Flush Cache"):
            st.session_state.transmission_history = []
            st.session_state.result = None
            st.session_state.message = ""
            st.rerun()


# ==========================================
# Existing Experimental Data Baseline
# ==========================================
if os.path.exists(CLEAN_FILE) and os.path.exists(LOSS_FILE):
    st.markdown('<div class="section-title">Reference Baselines (Archival)</div>', unsafe_allow_html=True)
    
    try:
        clean = pd.read_csv(CLEAN_FILE)
        loss = pd.read_csv(LOSS_FILE)

        clean["rtt_ms"] = pd.to_numeric(clean["rtt_ms"], errors="coerce")
        loss["rtt_ms"] = pd.to_numeric(loss["rtt_ms"], errors="coerce")

        clean_success = clean[clean["success"] == 1]
        loss_success = loss[loss["success"] == 1]

        sc1, sc2 = st.columns(2)
        with sc1:
            st.markdown("<p style='color: #cbd5e1; font-weight: 500;'>RTT Benchmark Profile</p>", unsafe_allow_html=True)
            rtt_chart = pd.DataFrame()
            rtt_chart["Ideal Network"] = clean_success.set_index("fragment")["rtt_ms"]
            rtt_chart["20% Degradation Condition"] = loss_success.set_index("fragment")["rtt_ms"]
            st.line_chart(rtt_chart, use_container_width=True)

        with sc2:
            st.markdown("<p style='color: #cbd5e1; font-weight: 500;'>Algorithm Delay Compensation</p>", unsafe_allow_html=True)
            delay_chart = pd.DataFrame()
            delay_chart["Ideal Network"] = clean.set_index("fragment")["adaptive_delay"]
            delay_chart["20% Degradation Condition"] = loss.set_index("fragment")["adaptive_delay"]
            st.line_chart(delay_chart, use_container_width=True)

        st.markdown("<p style='color: #cbd5e1; font-weight: 500; margin-top: 1rem;'>Loss Differential Profile</p>", unsafe_allow_html=True)
        clean_loss = clean["loss"].sum()
        loss_condition = loss["loss"].sum()

        clean_loss_rate = (clean_loss / len(clean)) * 100 if len(clean) > 0 else 0
        loss_condition_rate = (loss_condition / len(loss)) * 100 if len(loss) > 0 else 0

        saved_loss = pd.DataFrame({
            "Registered Loss Ratio (%)": [clean_loss_rate, loss_condition_rate]
        }, index=["Ideal Network", "20% Degradation Condition"])

        st.bar_chart(saved_loss, use_container_width=True)

    except Exception as e:
        st.error(f"Integrity error loading archival metrics: {e}")