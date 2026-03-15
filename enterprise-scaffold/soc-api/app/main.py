import uuid
import logging
from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from .database import engine, Base, get_db
from .models import User, Tenant, RoleEnum
from .models_alerts import SocAlert # Ensure this is imported for metadata creation
from .auth import (
    create_access_token, get_current_user,
    RoleChecker, ACCESS_TOKEN_EXPIRE_MINUTES, get_password_hash,
    verify_password
)
from .elastic import search_tenant_flows, get_tenant_stats
from .kafka_consumer import kafka_lifespan

logger = logging.getLogger("nf-soc-api")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="NetForensics SOC Core API", 
    description="Enterprise API Gateway. Controls Tenant access routing and Role Based operations.",
    version="5.0",
    lifespan=kafka_lifespan
)

@app.on_event("startup")
async def startup():
    # Asynchronously create the PostgreSQL schema 
    # (In production, replace with Alembic migrations)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# ─── Auth & Identity Management ─────────────────────────────────────────────

@app.post("/api/v1/auth/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: AsyncSession = Depends(get_db)
):
    """Exchanges an email + password for a Stateful JWT"""
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalars().first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Payload encodes organizational identity
    token_payload = {
        "sub": user.id,
        "tenant_id": user.tenant_id,
        "role": user.role.value
    }
    
    access_token = create_access_token(data=token_payload, expires_delta=access_token_expires)
    
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "tenant_id": user.tenant_id,
        "role": user.role.value
    }

@app.post("/api/v1/admin/bootstrap")
async def bootstrap_system(db: AsyncSession = Depends(get_db)):
    """Initializes an empty SOC environment with a default Tenant and Admin"""
    res = await db.execute(select(Tenant).where(Tenant.id == "org_default"))
    if res.scalars().first():
        return {"msg": "System already bootstrapped. Admin exists."}
        
    tenant = Tenant(id="org_default", name="Default Organization")
    admin = User(
        id=str(uuid.uuid4()),
        email="admin@netforensics.local",
        hashed_password=get_password_hash("admin123"), # Default pass
        role=RoleEnum.GLOBAL_ADMIN,
        tenant_id="org_default"
    )
    
    db.add(tenant)
    db.add(admin)
    await db.commit()
    return {"msg": "Successfully generated org_default", "credentials": "admin@netforensics.local / admin123"}

# ─── Multi-Tenant Data Retrieval Endpoints ──────────────────────────────────

@app.get("/api/v1/soc/stats")
async def get_dashboard_stats(
    user: User = Depends(RoleChecker([RoleEnum.ANALYST_L1, RoleEnum.ANALYST_L3, RoleEnum.TENANT_ADMIN]))
):
    """
    Retrieves global overview stats for the Tenant currently logged in.
    Automatically scopes the Elasticsearch aggregation to the User's tenant_id.
    """
    try:
        es_res = await get_tenant_stats(user.tenant_id)
        aggs = es_res.get("aggregations", {})
        
        return {
            "tenant_id": user.tenant_id,
            "total_bytes_transferred": aggs.get("total_bytes", {}).get("value", 0),
            "unique_endpoints": aggs.get("unique_src_ips", {}).get("value", 0),
            "top_protocols": aggs.get("protocols", {}).get("buckets", [])
        }
    except Exception as e:
        logger.error(f"Elasticsearch hit failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Data lake unavailable")

@app.get("/api/v1/soc/flows/top-talkers")
async def get_top_talkers(
    limit: int = 10,
    user: User = Depends(RoleChecker([RoleEnum.ANALYST_L1, RoleEnum.ANALYST_L3, RoleEnum.TENANT_ADMIN]))
):
    """Retrieves top source IPs by volume."""
    query = {
        "size": 0,
        "aggs": {
            "top_src_ips": {
                "terms": {
                    "field": "src_ip",
                    "size": limit,
                    "order": { "total_bytes": "desc" }
                },
                "aggs": {
                    "total_bytes": { "sum": { "field": "bytes_transferred" } }
                }
            }
        }
    }
    
    try:
        es_res = await search_tenant_flows(user.tenant_id, query)
        buckets = es_res.get("aggregations", {}).get("top_src_ips", {}).get("buckets", [])
        return {"tenant_id": user.tenant_id, "top_ips": buckets}
    except Exception as e:
        logger.error(f"Elasticsearch query failed: {e}")
        raise HTTPException(status_code=500, detail="Data lake unavailable")


@app.get("/api/v1/soc/pcaps/{flow_id}")
async def download_pcap(
    flow_id: str,
    # RBAC: ONLY Level 3 Analysts or Tenant Admins can do this!
    user: User = Depends(RoleChecker([RoleEnum.ANALYST_L3, RoleEnum.TENANT_ADMIN]))
):
    """
    Demonstrates RBAC. A Tier 1 Analyst calling this endpoint receives a 403 Forbidden, 
    preventing junior analysts from downloading raw payload data (ePHI/PII extraction vector).
    """
    # Simulate an S3 / MinIO Signed URL Generation mapped to the specific tenant
    return {
        "flow_id": flow_id,
        "tenant_id": user.tenant_id, 
        "download_url": f"https://s3.local/nf-pcaps-{user.tenant_id}/{flow_id}.pcap",
        "expires_in": 3600
    }
