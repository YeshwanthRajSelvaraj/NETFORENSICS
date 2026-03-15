import os
import json
import asyncio
import logging
from aiokafka import AIOKafkaConsumer

from .siem_forwarder import forward_to_splunk, trigger_webhook
from .taxii_server import convert_alert_to_stix

logger = logging.getLogger("nf-integrations")
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:29092")

async def forward_alerts():
    """Background listener routing Kafka alerts directly to external systems."""
    consumer = AIOKafkaConsumer(
        "nf.alerts",
        bootstrap_servers=KAFKA_BROKER,
        group_id="nf-integration-group",
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest"
    )

    retries = 5
    while retries > 0:
        try:
            await consumer.start()
            logger.info("✅ Integration Gateway Connected to Kafka")
            break
        except Exception as e:
            logger.warning(f"Connection retrying ({e})")
            retries -= 1
            await asyncio.sleep(5)
            
    if retries == 0:
        logger.error("❌ Fatal: SIEM Forwarder cannot reach Kafka")
        return

    try:
        async for msg in consumer:
            alert = msg.value
            
            # Action 1: Push to SIEMs (e.g., Splunk / Sentinel)
            await asyncio.create_task(forward_to_splunk(alert))
            await asyncio.create_task(trigger_webhook(alert))
            
            # Action 2: Convert to global IoC schema for TAXII sharing
            stix_objects = convert_alert_to_stix(alert)
            if stix_objects:
                logger.debug(f"Converted alert {alert['alert_id']} to {len(stix_objects)} STIX Observables.")
            
    finally:
        await consumer.stop()

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(forward_alerts())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
