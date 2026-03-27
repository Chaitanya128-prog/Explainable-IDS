import sys
import pandas as pd
from scapy.all import sniff
from colorama import init, Fore, Style

# Initialize colorama for colored terminal output
init()

from live_capture import PacketFeatureExtractor
from model import RealTimeIDSModel
from explainer import SHAPExplainer

CALIBRATION_PACKETS = 100 # Number of packets to see before starting detection

extractor = PacketFeatureExtractor()
model = RealTimeIDSModel(contamination=0.05)
explainer = None
calibration_data = []

print(f"{Fore.CYAN}=== Explainable AI Real-Time IDS ==={Style.RESET_ALL}")
print(f"Phase 1: Calibrating on {CALIBRATION_PACKETS} packets. Please generate some normal network traffic (e.g., browse the web).")

def process_packet(packet):
    global model, calibration_data, explainer
    
    features = extractor.extract_features(packet)
    if not features:
        return # Skip non-IP packets

    if not model.is_trained:
        calibration_data.append(features)
        sys.stdout.write(f"\rCollected {len(calibration_data)}/{CALIBRATION_PACKETS} packets for baseline...")
        sys.stdout.flush()
        
        if len(calibration_data) >= CALIBRATION_PACKETS:
            print(f"\n{Fore.GREEN}Calibration complete! Training Unsupervised ML Model (Isolation Forest)...{Style.RESET_ALL}")
            df_train = pd.DataFrame(calibration_data)
            
            # Train the real-time anomaly detector
            model.train(df_train)
            
            # Initialize the SHAP explainer
            explainer = SHAPExplainer(model.model)
            
            print(f"{Fore.CYAN}Model trained. Entering Phase 2: Active Real-Time Protection...{Style.RESET_ALL}")
            print(f"Listening for anomalies. Press Ctrl+C to stop.\n")
    else:
        # We are actively predicting
        df_instance = pd.DataFrame([features])
        prediction = model.predict(df_instance)[0]
        
        if prediction == -1: # -1 indicates an anomaly
            print(f"\n{Fore.RED}[!] ANOMALY DETECTED!{Style.RESET_ALL} (Packet length: {features['length']}, Proto: {'TCP' if features['is_tcp'] else 'UDP' if features['is_udp'] else 'ICMP' if features['is_icmp'] else 'Other'})")
            
            # Explain it with XAI
            exps = explainer.explain_instance(df_instance)
            print(f"{Fore.YELLOW}  XAI Explanation (Top 3 deciding features):{Style.RESET_ALL}")
            
            count = 0
            for feat, val in exps.items():
                if count >= 3: break
                direction = "decreased path length (more anomalous)" if val < 0 else "increased path length (more normal)"
                print(f"    -> {feat}: {val:.4f} [{direction}]")
                count += 1
            print("-" * 60)

if __name__ == "__main__":
    try:
        # Start sniffing, passing each packet to the process_packet callback
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Execution stopped by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error sniffing packets: {e}{Style.RESET_ALL}")
        print("Note: On Windows, make sure you have Npcap or Wireshark installed and run this terminal as Administrator!")