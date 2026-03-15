import enum
from sqlalchemy import Column, String, DateTime, Enum, JSON
from sqlalchemy.sql import func
from .database import Base

class AlertStatusEnum(str, enum.Enum):
    OPEN = "OPEN"               # New alert from AI worker
    INVESTIGATING = "INVESTIGATING" # Assigned to an analyst
    RESOLVED_FP = "RESOLVED_FP" # False Positive marker
    RESOLVED_TP = "RESOLVED_TP" # True Positive marker

class SocAlert(Base):
    """
    State table for alerts tracking human lifecycle.
    Unlike Elasticsearch (which is immutable logging), this table handles updates.
    """
    __tablename__ = "soc_alerts"
    
    id = Column(String(50), primary_key=True, index=True) # UUID from Kafka Event
    tenant_id = Column(String(50), nullable=False, index=True)
    engine_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    mitre_tactics = Column(JSON, nullable=False)
    mitre_techniques = Column(JSON, nullable=False)
    evidence = Column(JSON, nullable=False)
    affected_ips = Column(JSON, nullable=False)
    
    # Lifecycle Management
    status = Column(Enum(AlertStatusEnum), default=AlertStatusEnum.OPEN, nullable=False)
    assignee_id = Column(String(50), nullable=True) # Linked to Users table
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolution_notes = Column(String(1000), nullable=True)
