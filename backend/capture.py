import asyncio
from scapy.all import sniff, IP, TCP, UDP, Raw, load_layer, DNS, DNSQR, DNSRR
load_layer("tls")
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
import threading
from sqlalchemy.orm import Session
from .websockets import manager
from .database import SessionLocal
from .models import PacketLog, Alert
from .ai_model import ai_engine
import time
import socket
import logging

class AdvancedFeatureExtractor:
    def __init__(self):
        self.last_time = time.time()
        self.geo_cache = {} 
        self.dns_cache = {}
        self.global_domain_cache = {} # Maps IP -> Domain Name 
        try:
            from geolite2 import geolite2
            self.geo_reader = geolite2.reader()
        except:
            self.geo_reader = None

    def _get_geo(self, ip):
        """Map IP to Country and City offline"""
        if ip in self.geo_cache: return self.geo_cache[ip]
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
            geo_info = {"country": "Local", "country_code": "LOCAL", "city": "Network"}
            self.geo_cache[ip] = geo_info
            return geo_info
            
        geo_info = {"country": "Unknown", "country_code": "UNKNOWN", "city": "Unknown"}
        if self.geo_reader:
            try:
                match = self.geo_reader.get(ip)
                if match:
                    country = match.get("country", {}).get("names", {}).get("en", "Unknown")
                    country_code = match.get("country", {}).get("iso_code", "UNKNOWN")
                    city = match.get("city", {}).get("names", {}).get("en", "Unknown")
                    geo_info = {"country": country, "country_code": country_code, "city": city}
            except Exception:
                pass
                
        self.geo_cache[ip] = geo_info
        return geo_info

    def _background_resolve(self, ip):
        try:
            host = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = host
            self.global_domain_cache[ip] = host
        except:
            self.dns_cache[ip] = ip

    def _resolve_ip_nonblocking(self, ip):
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
            return "Local Network Device"
            
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        self.dns_cache[ip] = ip # Temporary fallback
        threading.Thread(target=self._background_resolve, args=(ip,), daemon=True).start()
        return ip
        
    def _classify_domain(self, domain):
        if not domain or domain == 'Cleartext HTTP' or domain == "Local Network Device":
            return "UNKNOWN"
            
        domain = domain.lower()
        safe_domains = ['google', 'youtube', 'facebook', 'github', 'microsoft', 'apple', 'amazon', 'cloudflare', 'aws', 'netflix', 'linkedin', 'twitter']
        
        for safe in safe_domains:
            if safe in domain:
                return "SAFE"
                
        if len(domain) > 35 or domain.count('-') > 3 or any(char.isdigit() for char in domain[0:5]):
            return "SUSPICIOUS"
            
        return "UNKNOWN"

    def extract_features(self, packet):
        if not packet.haslayer(IP):
            return None, None
            
        current_time = time.time()
        inter_arrival_time = current_time - self.last_time
        self.last_time = current_time
        
        ip_layer = packet.getlayer(IP)
        length = len(packet)
        ttl = ip_layer.ttl
        
        protocol = ip_layer.proto
        is_tcp = 1 if protocol == 6 else 0
        is_udp = 1 if protocol == 17 else 0
        is_icmp = 1 if protocol == 1 else 0
        proto_name = "TCP" if is_tcp else ("UDP" if is_udp else ("ICMP" if is_icmp else "Other"))
        
        src_port, dst_port, tcp_flags = 0, 0, 0
        domain_sni = None
        
        if packet.haslayer(DNS) and packet.haslayer(DNSRR):
            try:
                for i in range(packet[DNS].ancount):
                    rr = packet[DNSRR][i]
                    if rr.type == 1: # A record
                        domain_name = rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                        ip_addr = rr.rdata
                        self.global_domain_cache[ip_addr] = domain_name
            except Exception:
                pass

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port, dst_port = tcp_layer.sport, tcp_layer.dport
            tcp_flags = int(tcp_layer.flags)
            if packet.haslayer(TLSClientHello):
                if packet.haslayer(TLS_Ext_ServerName):
                    server_names = packet.getlayer(TLS_Ext_ServerName).servernames
                    if server_names:
                        domain_sni = server_names[0].servername.decode('utf-8', errors='ignore')
                        self.global_domain_cache[ip_layer.dst] = domain_sni
                elif packet.haslayer(Raw) and b"HTTP/" in packet.getlayer(Raw).load:
                    domain_sni = "Cleartext HTTP"
                        
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port, dst_port = udp_layer.sport, udp_layer.dport
            if packet.haslayer(DNSQR):
                qname = packet.getlayer(DNSQR).qname
                if qname:
                    domain_sni = qname.decode('utf-8', errors='ignore').rstrip('.')

        # Cross-packet domain resolution using our cache!
        if not domain_sni:
            if ip_layer.dst in self.global_domain_cache:
                domain_sni = self.global_domain_cache[ip_layer.dst]
            elif ip_layer.src in self.global_domain_cache:
                domain_sni = self.global_domain_cache[ip_layer.src]

        geo = self._get_geo(ip_layer.dst)
        
        if not domain_sni:
            domain_sni = self._resolve_ip_nonblocking(ip_layer.dst)
            
        domain_trust = self._classify_domain(domain_sni)

        features = {
            "length": length, "ttl": ttl, "is_tcp": is_tcp, "is_udp": is_udp, 
            "is_icmp": is_icmp, "src_port": src_port, "dst_port": dst_port, 
            "tcp_flags": tcp_flags, "inter_arrival_time": inter_arrival_time
        }
        
        raw_info = {
            "src_ip": ip_layer.src, "dst_ip": ip_layer.dst, "protocol": proto_name,
            "src_port": src_port, "dst_port": dst_port, "length": length,
            "domain_sni": domain_sni, "domain_trust": domain_trust, 
            "country": geo["country"], "country_code": geo["country_code"], 
            "city": geo["city"]
        }
        
        return features, raw_info

extractor = AdvancedFeatureExtractor()
packet_queue = asyncio.Queue()
calibration_buffer = []
main_loop = None
engine_active = True

async def toggle_engine():
    global engine_active
    engine_active = not engine_active
    state = "Active & Live" if engine_active else "Paused"
    await manager.broadcast({"type": "ENGINE_STATE", "data": state})
    return state

def packet_callback(packet):
    global engine_active, main_loop
    if not engine_active:
        return
    try:
        feat, raw = extractor.extract_features(packet)
        # Software-level loopback filter due to Windows Npcap BPF bugs
        if feat and raw:
            ignore_ports = {8000, 8001, 8002, 8003, 8004, 8005, 8006, 5173, 5174, 5175, 5176}
            if raw.get("src_port") in ignore_ports or raw.get("dst_port") in ignore_ports:
                return
                
        if feat and main_loop and not main_loop.is_closed():
            main_loop.call_soon_threadsafe(packet_queue.put_nowait, (feat, raw))
    except Exception as e:
        logging.error(f"Callback error: {e}")

async def process_packets():
    import pandas as pd
    from .explainer import explainer_engine
    while True:
        try:
            feat, raw = await packet_queue.get()
            df_instance = pd.DataFrame([feat])
            
            # Calibration Logic
            if not ai_engine.is_trained:
                calibration_buffer.append(feat)
                threat_status, attack_type = "Normal", "Calibrating"
                
                if len(calibration_buffer) >= 50:
                    df_train = pd.DataFrame(calibration_buffer)
                    ai_engine.train(df_train)
                    explainer_engine.initialize(ai_engine.model)
                    await manager.broadcast({"type": "CALIBRATION_COMPLETE", "data": "Model online"})
            else:
                threat_status, attack_type = ai_engine.predict(df_instance, raw)
            
            # Generate Explanation for Anomalies
            explanation = {}
            if threat_status in ["Suspicious", "Malicious"] and ai_engine.is_trained:
                explanation = explainer_engine.explain_instance(df_instance)
                raw["explanation"] = explanation
            
            db = SessionLocal()
            new_log = PacketLog(
                src_ip=raw["src_ip"], dst_ip=raw["dst_ip"], src_port=raw["src_port"],
                dst_port=raw["dst_port"], protocol=raw["protocol"], length=raw["length"],
                domain_sni=raw["domain_sni"], country=raw["country"],
                threat_status=threat_status, attack_type=attack_type
            )
            db.add(new_log)
            db.commit()
            db.refresh(new_log)
            
            # Broadcast Alert if malicious/suspicious
            if threat_status in ["Malicious", "Suspicious"]:
                severity = "High" if threat_status == "Malicious" else "Medium"
                msg = f"Detected {attack_type} from {raw['src_ip']} to {raw['dst_ip']}"
                new_alert = Alert(severity=severity, message=msg, packet_id=new_log.id)
                db.add(new_alert)
                db.commit()
                db.refresh(new_alert)
                await manager.broadcast({
                    "type": "ALERT",
                    "data": {"id": new_alert.id, "severity": severity, "message": msg, "timestamp": str(new_alert.timestamp)}
                })
                
            # Rate spike heuristic
            global last_spike_time
            if 'last_spike_time' not in globals():
                last_spike_time = 0
            current_time = time.time()
            if current_time - last_spike_time > 10.0 and packet_queue.qsize() > 500:
                last_spike_time = current_time
                await manager.broadcast({
                    "type": "ALERT",
                    "data": {"id": 99999, "severity": "Medium", "message": f"Traffic spike detected! {packet_queue.qsize()} packets queued instantly.", "timestamp": str(new_log.timestamp)}
                })

            
            raw["id"] = new_log.id
            raw["threat_status"] = threat_status
            raw["attack_type"] = attack_type
            raw["timestamp"] = str(new_log.timestamp)
            
            db.close()
            
            await manager.broadcast({
                "type": "NEW_PACKET",
                "data": raw
            })
        except Exception as e:
            logging.error(f"Packet Processing error: {e}")

def start_sniffer():
    global main_loop
    try:
        main_loop = asyncio.get_running_loop()
    except RuntimeError:
        main_loop = asyncio.get_event_loop()
        
    import threading
    bpf_filter = "not (tcp port 8000 or tcp port 8001 or tcp port 8002 or tcp port 8003 or tcp port 8004 or tcp port 8005 or tcp port 8006 or tcp port 5173 or tcp port 5174 or tcp port 5175)"
    t = threading.Thread(target=lambda: sniff(filter=bpf_filter, prn=packet_callback, store=False), daemon=True)
    t.start()
    logging.info("Packet sniffer background thread started.")
