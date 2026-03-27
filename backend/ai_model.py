import pandas as pd
from sklearn.ensemble import IsolationForest
import time
from backend.models import PacketLog
from sqlalchemy.orm import Session

class HybridIDSModel:
    def __init__(self, contamination=0.05):
        # Unsupervised base
        self.model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        self.is_trained = False
        self.feature_names = None
        
        # Heuristic state for true multi-class without labeled data
        self.ip_syn_counts = {}
        self.ip_total_traffic = {}
        self.last_reset = time.time()

    def train(self, df: pd.DataFrame):
        """ Trains the unsupervised baseline """
        self.feature_names = df.columns.tolist()
        self.model.fit(df)
        self.is_trained = True
        
    def _check_heuristics(self, features: dict, raw_packet_info: dict) -> str:
        current_time = time.time()
        # Reset trackers every 10 seconds to avoid memory leak and keep rolling window
        if current_time - self.last_reset > 10: 
            self.ip_syn_counts.clear()
            self.ip_total_traffic.clear()
            self.last_reset = current_time

        src_ip = raw_packet_info.get("src_ip", "Unknown")
        
        # 1. Port Scan Detection (Many SYN packets in a short time from same IP)
        if features.get("is_tcp") and features.get("tcp_flags") == 2: # 2 is the SYN flag
            self.ip_syn_counts[src_ip] = self.ip_syn_counts.get(src_ip, 0) + 1
            if self.ip_syn_counts[src_ip] > 30: 
                return 'Port Scan'

        # 2. DDoS Detection (High volume of traffic from a single IP rapidly)
        self.ip_total_traffic[src_ip] = self.ip_total_traffic.get(src_ip, 0) + 1
        if self.ip_total_traffic[src_ip] > 150: 
            return 'DDoS'
            
        return None

    def predict(self, df: pd.DataFrame, raw_packet_info: dict) -> tuple:
        """ Returns (threat_status, attack_type) tuple """
        features = df.iloc[0].to_dict()
        
        # Step 1: Check known heuristic signatures (Supervised pseudo-logic)
        heuristic_attack = self._check_heuristics(features, raw_packet_info)
        if heuristic_attack:
            return ("Malicious", heuristic_attack)

        # Step 2: Fallback to unsupervised zero-day anomaly detection
        if self.is_trained:
            pred = self.model.predict(df)[0]
            if pred == -1:
                return ("Suspicious", "Zero-day / Anomaly")
                
        return ("Normal", None)

# Initialize a global singleton engine
ai_engine = HybridIDSModel()
