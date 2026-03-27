import time
from scapy.all import IP, TCP, UDP, ICMP

class PacketFeatureExtractor:
    def __init__(self):
        self.last_time = time.time()
        
    def extract_features(self, packet):
        """
        Extracts numerical features from a scapy packet.
        Returns a dictionary of features or None if it's not an IP packet.
        """
        if not packet.haslayer(IP):
            return None
            
        current_time = time.time()
        inter_arrival_time = current_time - self.last_time
        self.last_time = current_time
        
        # Base features
        ip_layer = packet.getlayer(IP)
        length = len(packet)
        ttl = ip_layer.ttl
        
        # Protocol categorization (TCP=6, UDP=17, ICMP=1)
        protocol = ip_layer.proto
        is_tcp = 1 if protocol == 6 else 0
        is_udp = 1 if protocol == 17 else 0
        is_icmp = 1 if protocol == 1 else 0
        
        # Port and flags information
        src_port = 0
        dst_port = 0
        tcp_flags = 0
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            # tcp.flags is usually an integer representation or FlagValue
            tcp_flags = int(tcp_layer.flags)
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
        return {
            "length": length,
            "ttl": ttl,
            "is_tcp": is_tcp,
            "is_udp": is_udp,
            "is_icmp": is_icmp,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "inter_arrival_time": inter_arrival_time
        }
