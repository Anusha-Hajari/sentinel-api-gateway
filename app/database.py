import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

# Uses SQLite by default for zero-friction local execution.
# To connect to your local PostgreSQL, set:
# DATABASE_URL="postgresql://postgres:yourpassword@localhost:5432/sentinel_db"

DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres:postgres@localhost:5432/sentinel_db"
)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    client_ip = Column(String(50), index=True)
    method = Column(String(10))
    path = Column(String(255))
    attack_type = Column(String(50))   # "SQLi", "XSS", "Cmd_Traversal", "CSIC Anomalous Attack"
    confidence = Column(Float)
    anomaly_score = Column(Float)
    payload_sample = Column(Text)
    action_taken = Column(String(20))  # "BLOCKED" or "FLAGGED"


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), unique=True, index=True)
    reason = Column(String(255))
    blocked_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()