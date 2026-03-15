import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from aiokafka import AIOKafkaConsumer

from .database import AsyncSessionLocal
from .models_alerts import SocAlert, AlertStatusEnum

logger = logging.getLogger("nf-alert-ingester")

# We run a background Kafka consumer inside the FastAPI SOC runtime
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:29092")

async def consume_alerts():
    """Background task pulling exclusively from nf.alerts (AI Worker Output)"""
    consumer = AIOKafkaConsumer(
        "nf.alerts",
        bootstrap_servers=KAFKA_BROKER,
        group_id="nf-soc-api-group",
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest"
    )
    
    # Retry mechanism for bootstrapping
    retries = 5
    while retries > 0:
        try:
            await consumer.start()
            logger.info("✅ SOC API Connected to Kafka Topic: nf.alerts")
            break
        except Exception as e:
            retries -= 1
            logger.warning(f"Consumer start failed, retrying in 5s... ({e})")
            await asyncio.sleep(5)
            
    if retries == 0:
        logger.error("❌ Fatal: SOC API could not connect to Kafka Broker for Alerts.")
        return

    try:
        async for msg in consumer:
            alert_data = msg.value
            
            # Map the raw Kafka event JSON into a PostgreSQL Relational Row
            async with AsyncSessionLocal() as session:
                try:
                    new_alert = SocAlert(
                        id=alert_data["alert_id"],
                        tenant_id=alert_data["tenant_id"],
                        engine_name=alert_data["engine_name"],
                        severity=alert_data["severity"],
                        title=alert_data["title"],
                        mitre_tactics=alert_data["mitre_tactics"],
                        mitre_techniques=alert_data["mitre_techniques"],
                        evidence=alert_data["evidence"],
                        affected_ips=alert_data["affected_ips"],
                        status=AlertStatusEnum.OPEN
                    )
                    session.add(new_alert)
                    await session.commit()
                    logger.info(f"🚨 New Alert inserted to PG: {new_alert.title} (Tenant: {new_alert.tenant_id})")
                
                except Exception as e:
                    await session.rollback()
                    # Ignore Duplicate Key UUID errors (Kafka At-Least-Once Delivery guarantees)
                    if "UniqueViolationError" not in str(e):
                        logger.error(f"Postgres insertion error: {e}")

    finally:
        await consumer.stop()

# Used by main.py to manage the lifecycle of the background consumer
@asynccontextmanager
async def kafka_lifespan(app):
    task = asyncio.create_task(consume_alerts())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    logger.info("Kafka consumer shut down gracefully.")
