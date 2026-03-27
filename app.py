import streamlit as st
import pandas as pd
import time
from threading import Thread
import queue
from scapy.all import sniff
from scapy.interfaces import get_working_ifaces
import matplotlib.pyplot as plt

# Custom Modules
from live_capture import PacketFeatureExtractor
from model import RealTimeIDSModel
from explainer import SHAPExplainer

st.set_page_config(page_title="Explainable AI IDS", page_icon="🛡️", layout="wide")

st.title("🛡️ Explainable AI-Based Intrusion Detection System")
st.markdown("Real-time network traffic analysis using Machine Learning and Explainable AI (SHAP).")

# --- Thread-Safe Globals (accessible natively by background threads) ---
@st.cache_resource
def get_packet_queue():
    return queue.Queue()
packet_queue = get_packet_queue()

@st.cache_resource
def get_error_log():
    return []
error_log = get_error_log()

@st.cache_resource
def get_extractor():
    return PacketFeatureExtractor()
extractor = get_extractor()

# --- Session State (only accessed by main Streamlit thread) ---
if 'model' not in st.session_state:
    st.session_state.model = RealTimeIDSModel(contamination=0.05)
if 'explainer' not in st.session_state:
    st.session_state.explainer = None
if 'calibration_data' not in st.session_state:
    st.session_state.calibration_data = []
if 'is_calibrating' not in st.session_state:
    st.session_state.is_calibrating = False
if 'is_monitoring' not in st.session_state:
    st.session_state.is_monitoring = False
if 'recent_traffic' not in st.session_state:
    st.session_state.recent_traffic = []
if 'latest_anomaly' not in st.session_state:
    st.session_state.latest_anomaly = None
if 'active_iface_label' not in st.session_state:
    st.session_state.active_iface_label = None

# --- Background Sniffing ---
def packet_callback(packet):
    features = extractor.extract_features(packet)
    if features:
        packet_queue.put(features)

def sniff_worker(iface_obj):
    try:
        if iface_obj == "Default":
            sniff(prn=packet_callback, store=False)
        else:
            sniff(iface=iface_obj, prn=packet_callback, store=False)
    except Exception as e:
        import traceback
        error_log.append(traceback.format_exc())

def start_background_sniffing(iface_obj):
    error_log.clear() # clear past errors on restart
    t = Thread(target=sniff_worker, args=(iface_obj,), daemon=True)
    t.start()
    return t

# --- Sidebar: Network Interface Selection ---
try:
    ifaces = get_working_ifaces()
    iface_dict = {"All Interfaces / Default": "Default"}
    for i in ifaces:
        desc = getattr(i, 'description', i.name)
        iface_dict[f"{desc} ({i.name})"] = i
except Exception:
    iface_dict = {"All Interfaces / Default": "Default"}

st.sidebar.header("⚙️ Network Settings")
st.sidebar.write("If the progress stays at 0/50, try selecting your Wi-Fi or Ethernet adapter below and click Restart.")
selected_iface_label = st.sidebar.selectbox("Select Network Adapter", list(iface_dict.keys()))

if st.sidebar.button("Restart Sniffer"):
    st.session_state.active_iface_label = selected_iface_label
    # Clear queue so we don't mix old data
    while not packet_queue.empty():
        packet_queue.get()
    start_background_sniffing(iface_dict[selected_iface_label])
    st.sidebar.success(f"Sniffer restarted on {selected_iface_label}!")

if st.session_state.active_iface_label is None:
    st.session_state.active_iface_label = "All Interfaces / Default"
    start_background_sniffing("Default")

if error_log:
    st.error(f"Packet sniffer error:\n{error_log[-1]}")
    st.warning("Note: On Windows, you typically need to run this script as Administrator to sniff packets, and ensure Npcap (or Wireshark) is installed.")

# --- UI Layout ---
col1, col2, col3 = st.columns(3)

with col1:
    st.info("### 1. ML Detection Engine")
    st.write("Analyzes network traffic and classifies it as normal or malicious.")
    
    calib_packets_needed = st.number_input("Calibration Packets Needed", min_value=10, max_value=1000, value=50)
    
    if st.button("Start Calibration (Learn Baseline)"):
        st.session_state.calibration_data = []
        st.session_state.is_calibrating = True
        st.session_state.is_monitoring = False
        st.session_state.model = RealTimeIDSModel(contamination=0.05) # reset
        st.session_state.explainer = None
    
    # Process calibration 
    if st.session_state.is_calibrating:
        while not packet_queue.empty() and len(st.session_state.calibration_data) < calib_packets_needed:
            st.session_state.calibration_data.append(packet_queue.get())
            
        count = len(st.session_state.calibration_data)
        st.progress(min(count / calib_packets_needed, 1.0))
        st.write(f"Collecting normal traffic: {count}/{calib_packets_needed} packets")
        
        if count >= calib_packets_needed:
            st.session_state.is_calibrating = False
            df_train = pd.DataFrame(st.session_state.calibration_data)
            st.session_state.model.train(df_train)
            st.session_state.explainer = SHAPExplainer(st.session_state.model.model)
            st.success("Isolation Forest Model Trained on Normal Traffic Baseline!")
        else:
            time.sleep(0.5)
            st.rerun()

with col2:
    st.success("### 2. Visualization & Alerts")
    st.write("Displays live detection results, metrics, and network traffic dashboards.")
    
    if st.button("Start Real-Time Detection"):
        if not st.session_state.model.is_trained:
            st.error("Please calibrate the model first!")
        else:
            st.session_state.is_monitoring = True
            
    if st.button("Stop Monitoring"):
        st.session_state.is_monitoring = False

with col3:
    st.warning("### 3. Explainable AI Module")
    st.write("Provides transparency by explaining why a network instance is classified as an attack.")

# --- Main Dashboard Area ---
st.divider()

if st.session_state.is_monitoring:
    st.subheader("Live Network Traffic Dashboard")
    
    # Process up to 20 incoming packets per rerun to avoid lagging
    packets_processed = 0
    while not packet_queue.empty() and packets_processed < 20:
        pkt = packet_queue.get()
        df_instance = pd.DataFrame([pkt])
        pred = st.session_state.model.predict(df_instance)[0]
        
        pkt_display = pkt.copy()
        pkt_display['Status'] = 'Normal' if pred == 1 else 'Anomaly'
        st.session_state.recent_traffic.append(pkt_display)
        
        if pred == -1:
            # Generate explanation for anomalies
            exps = st.session_state.explainer.explain_instance(df_instance)
            st.session_state.latest_anomaly = (pkt_display, exps)
            
        packets_processed += 1
        
    # Keep only the last 50 packets to save memory
    if len(st.session_state.recent_traffic) > 50:
         st.session_state.recent_traffic = st.session_state.recent_traffic[-50:]
         
    # Display recent traffic table
    if st.session_state.recent_traffic:
        df_display = pd.DataFrame(st.session_state.recent_traffic).iloc[::-1] # Reverse chronologically
        
        # Color code anomalies in dataframe
        def color_anomalies(val):
            color = 'red' if val == 'Anomaly' else 'lightgreen'
            return f'color: {color}'
            
        try:
             # pandas >= 1.3
             st.dataframe(df_display.style.map(color_anomalies, subset=['Status']), use_container_width=True)
        except AttributeError:
             # pandas < 1.3
             st.dataframe(df_display.style.applymap(color_anomalies, subset=['Status']), use_container_width=True)

    # Render Explanation in Col3
    if st.session_state.latest_anomaly is not None:
        with col3:
            pkt, exps = st.session_state.latest_anomaly
            st.error(f"🚨 Anomaly Detected! (Len: {pkt['length']})")
            
            # Bar chart of SHAP values
            features = list(exps.keys())[:5]
            values = list(exps.values())[:5] # These are already sorted by absolute value
            
            fig, ax = plt.subplots(figsize=(6, 4))
            colors = ['#ff9999' if v < 0 else '#99ff99' for v in values]
            ax.barh(features[::-1], values[::-1], color=colors[::-1]) # Reverse to show biggest at top
            ax.set_title("SHAP Feature Contributions")
            ax.set_xlabel("SHAP Value (Negative = Anomaly)")
            st.pyplot(fig)
            plt.close(fig)
            st.write("*Features highlighted in red strongly push the model to flag this connection as an anomaly.*")

    time.sleep(1) # Rerun freq
    st.rerun()
