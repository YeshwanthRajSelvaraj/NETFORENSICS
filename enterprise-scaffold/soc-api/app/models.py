from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Enum, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from .database import Base

class RoleEnum(str, enum.Enum):
    GLOBAL_ADMIN = "GLOBAL_ADMIN"      # Platform engineers, cross-tenant visibility
    TENANT_ADMIN = "TENANT_ADMIN"      # Customer admins, manages users in their Org
    ANALYST_L3   = "ANALYST_L3"        # Senior hunter. Full access to raw PCAP downloads
    ANALYST_L1   = "ANALYST_L1"        # Triage analyst. View metadata and alerts only

class Tenant(Base):
    __tablename__ = "tenants"
    
    id = Column(String(50), primary_key=True, index=True) # E.g., 'org_1234abcd'
    name = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="tenant", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"
    
    id = Column(String(50), primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.ANALYST_L1, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    tenant_id = Column(String(50), ForeignKey("tenants.id"))
    tenant = relationship("Tenant", back_populates="users")

class APIKey(Base):
    """Used for external systems (e.g., SIEM forwarders, Sensor agents) auth."""
    __tablename__ = "api_keys"
    
    id = Column(String(50), primary_key=True, index=True)
    key_hash = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    tenant_id = Column(String(50), ForeignKey("tenants.id"), nullable=False)
    tenant = relationship("Tenant", back_populates="api_keys")
