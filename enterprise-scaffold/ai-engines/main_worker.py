import os
import uuid
import logging
import faust
from datetime import datetime
from pydantic import BaseModel
import networkx as nx

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nf-ai-worker")

KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "kafka://localhost:29092")

# ─── Data Models (Faust Records) ─────────────────────────────────────────────

# Faust models automatically handle JSON payload serialization/deserialization.
# These models align exactly with the Phase 1 Ingestion Gateway outputs.
class FlowEvent(faust.Record, serializer='json'):
    tenant_id: str
    sensor_id: str
    ingestion_timestamp: float
    start_time: float
    end_time: float
    duration: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    bytes_transferred: int

class AlertEvent(faust.Record, serializer='json'):
    alert_id: str
    engine_name: str
    severity: str
    title: str
    description: str
    mitre_tactics: list
    mitre_techniques: list
    evidence: dict
    affected_ips: list
    tenant_id: str

# ─── Application Setup ───────────────────────────────────────────────────────

# Initialize the Faust streaming application
app = faust.App(
    "netforensics-ai-worker",
    broker=KAFKA_BROKER,
    value_serializer='json',
    stream_wait_empty=False,
    topic_partitions=3,     # Match the Phase 1 partition layout
)

# Define the source and sink topics
# We read from nf.flows and publish back to nf.alerts
flows_topic = app.topic("nf.flows", value_type=FlowEvent)
alerts_topic = app.topic("nf.alerts", value_type=AlertEvent)

# ─── Stateful Windowing (Building Behavioral Baselines) ─────────────────────

# A Tumbling Window keeps state for a set period (e.g., 5 minutes).
# This table automatically partitions data by `tenant_id` ensuring 
# organizations' behavioral baselines are mathematically isolated.
# It tracks the unique IPs contacted by a source.
ip_contact_table = app.Table(
    "ip_contacts_5min",
    default=set,
    partitions=3,
).tumbling(5 * 60, expires=timedelta(minutes=15))

# ─── AI Worker Logic ─────────────────────────────────────────────────────────

@app.agent(flows_topic)
async def process_flows_for_hunting(flows):
    """
    Streaming AI Worker - Autonomous Threat Hunter
    Asynchronously processes network flows to detect statistical anomalies.
    """
    async for flow in flows:
        # Example 1: Updating the stateful table
        # We track how many unique destinations a source IP contacts within the 5m window.
        # Flow.src_ip is bounded implicitly by the Tenant partition.
        current_state = ip_contact_table[flow.tenant_id + ":" + flow.src_ip].value()
        current_state.add(flow.dst_ip)
        ip_contact_table[flow.tenant_id + ":" + flow.src_ip] = current_state

        # --- Fast Path Detection (Stateless Pattern Matching) ---
        
        # Detect Data Exfiltration (Simple heuristic example: huge upload, tiny duration)
        if flow.bytes_transferred > 50_000_000 and flow.duration < 10.0:
            logger.warning(f"Exfiltration anomaly detected for Tenant {flow.tenant_id} on IP {flow.src_ip}")
            
            alert = AlertEvent(
                alert_id=str(uuid.uuid4()),
                engine_name="StreamingAnomalyHunter",
                severity="HIGH",
                title="Suspicious Data Transfer Burst",
                description=f"IP {flow.src_ip} transferred {flow.bytes_transferred / 1e6:.2f} MB in {flow.duration:.1f}s to {flow.dst_ip}.",
                mitre_tactics=["Exfiltration"],
                mitre_techniques=["T1048"],
                evidence={
                    "duration": flow.duration,
                    "bytes": flow.bytes_transferred,
                    "bps": flow.bytes_transferred / max(0.1, flow.duration)
                },
                affected_ips=[flow.src_ip, flow.dst_ip],
                tenant_id=flow.tenant_id
            )
            # Push finding back into the Kafka pipeline for the SOC API to consume
            await alerts_topic.send(value=alert)


# ─── Graph AI Engine Integration ─────────────────────────────────────────────

# Instead of recalculating PageRank on every packet (which destroys performance),
# we batch flows every 60 seconds using a timer to perform structural graph analysis.

graph_batch = app.Table("graph_batch", default=list, partitions=3).tumbling(60, expires=timedelta(minutes=5))

@app.agent(flows_topic)
async def batch_for_graph_ai(flows):
    """Batches raw flows specifically for deep structural analysis."""
    async for flow in flows:
        # Append to the rolling 60s list of edges
        edges = graph_batch[flow.tenant_id].value()
        edges.append((flow.src_ip, flow.dst_ip, flow.bytes_transferred))
        graph_batch[flow.tenant_id] = edges

@app.timer(interval=60.0)
async def periodic_graph_analysis():
    """Timer fires every 60s to execute NetworkX structural anomaly detection"""
    for tenant_id, window in graph_batch.items():
        edges = window.current()
        if not edges or len(edges) < 10:
            continue
            
        logger.info(f"Running Graph AI on {len(edges)} edges for Tenant {tenant_id}")
        
        # Reconstruct the behavioral graph
        G = nx.DiGraph()
        for src, dst, weight in edges:
            G.add_edge(src, dst, weight=weight)
            
        # Example Structural Anomaly: Fan-Out / Scanner
        # Node contacts many others, but nobody contacts it back.
        out_degrees = dict(G.out_degree())
        
        for node, degree in out_degrees.items():
            if degree > 50:  # Threshold representing potentially highly connected scanner or malware
                alert = AlertEvent(
                    alert_id=str(uuid.uuid4()),
                    engine_name="GraphAI_Structural",
                    severity="MEDIUM",
                    title="Anomalous Fan-Out Structure Detected",
                    description=f"IP {node} originated connections to {degree} unique endpoints within 60 seconds.",
                    mitre_tactics=["Discovery", "Command and Control"],
                    mitre_techniques=["T1046", "T1090"],
                    evidence={"out_degree": degree, "graph_nodes": G.number_of_nodes()},
                    affected_ips=[node],
                    tenant_id=tenant_id
                )
                await alerts_topic.send(value=alert)
        
        # Clear the batch after processing
        graph_batch[tenant_id] = []

if __name__ == '__main__':
    app.main()
