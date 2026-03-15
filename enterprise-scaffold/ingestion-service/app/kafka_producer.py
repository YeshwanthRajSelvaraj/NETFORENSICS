import logging
import asyncio
from typing import Dict, Any, List
import orjson
from aiokafka import AIOKafkaProducer

logger = logging.getLogger("nf-ingestion.kafka")

class KafkaService:
    def __init__(self, bootstrap_servers: str = "localhost:29092"):
        self.bootstrap_servers = bootstrap_servers
        self.producer = None
        self._connected = False

    async def connect(self):
        """Initialize the async Kafka producer with retries and compression"""
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            # Use fast JSON serialization
            value_serializer=lambda v: orjson.dumps(v),
            # Key serializer for sticky partitioning by Tenant ID
            key_serializer=lambda k: k.encode('utf-8') if k else None,
            # Compression saves massive bandwidth for flow logs
            compression_type="zstd",
            # Enterprise durability: Wait for all replicas to ack
            acks="all",
            # Batches up to 1MB or waiting 50ms (for throughput)
            linger_ms=50,
            batch_size=1048576,
        )
        
        retries = 5
        while retries > 0:
            try:
                await self.producer.start()
                self._connected = True
                logger.info("Successfully connected to Kafka cluster at %s", self.bootstrap_servers)
                return
            except Exception as e:
                logger.error("Failed to connect to Kafka. Retries left: %d. Error: %s", retries, e)
                retries -= 1
                await asyncio.sleep(3)
        
        raise RuntimeError("Could not connect to Kafka after multiple retries.")

    async def disconnect(self):
        if self.producer and self._connected:
            await self.producer.stop()
            self._connected = False
            logger.info("Disconnected from Kafka cluster.")

    async def publish_events(self, topic: str, tenant_id: str, events: List[Dict[str, Any]]):
        """Asynchronously publish a batch of events to Kafka"""
        if not self._connected:
            raise ConnectionError("Kafka producer is not connected.")

        try:
            # We partition by tenant_id. This guarantees all events for a tenant 
            # land in the same partition, ensuring order is preserved per-tenant.
            batch = self.producer.create_batch()
            tasks = []
            
            for event in events:
                # Fire and forget (it goes into the local buffer based on linger_ms)
                tasks.append(self.producer.send(
                    topic=topic,
                    key=tenant_id,  # Sticky Partitioning
                    value=event
                ))
            
            # Wait for the futures to resolve (i.e. buffered or sent)
            await asyncio.gather(*tasks)
            logger.debug("Successfully published %d events to %s", len(events), topic)
            
        except Exception as e:
            logger.exception("Error publishing to Kafka topic %s: %s", topic, str(e))
            raise

kafka_service = KafkaService()
