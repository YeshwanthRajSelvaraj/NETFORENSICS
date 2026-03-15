from fastapi import FastAPI, HTTPException
import json

from .taxii_server import generate_taxii_bundle
from .kafka_listener import lifespan

app = FastAPI(
    title="NetForensics Integration Gateway",
    description="STIX/TAXII Server and SIEM Webhook forwarder",
    version="5.0",
    lifespan=lifespan
)

@app.get("/taxii2/collections/system/objects", response_model=dict)
async def get_stix_observables():
    """
    STIX 2.1 Polling Endpoint.
    External tools (like Palo Alto Minemeld or an upstream MSSP) ping this endpoint
    to pull down the latest Indicators of Compromise (C2 IPs) detected by our AI workers.
    """
    try:
        # Pull the serialized STIX 2.1 bundle from the MemoryStore
        bundle_str = generate_taxii_bundle()
        # Fast API handles the JSON Response return natively
        return json.loads(bundle_str)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "Integration Gateway Active"}
