from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean
from .database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user") # 'admin' or 'user'

class PacketLog(Base):
    __tablename__ = "packet_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    length = Column(Integer)
    domain_sni = Column(String, nullable=True) # E.g., google.com via SNI
    country = Column(String, nullable=True)     # Geolocation info
    threat_status = Column(String)             # 'Normal', 'Suspicious', 'Malicious'
    attack_type = Column(String, nullable=True) # 'DDoS', 'Port Scan', etc.

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    severity = Column(String) # 'Low', 'Medium', 'High'
    message = Column(String)
    packet_id = Column(Integer, nullable=True) # Reference to specific packet if any
    is_resolved = Column(Boolean, default=False)
