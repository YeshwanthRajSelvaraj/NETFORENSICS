import json
import argparse
import sys
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable
import time

BOOTSTRAP_SERVERS = "localhost:29092"
TOPICS = ["nf.raw_packets", "nf.flows", "nf.alerts", "nf.tls", "nf.dns"]

def main(topic_filter: str):
    print(f"[*] Starting Kafka Consumer Debug Tool")
    print(f"[*] Bootstrapping to brokers: {BOOTSTRAP_SERVERS}")
    
    # Try to connect with a 5-second backoff
    connected = False
    retries = 3
    consumer = None
    
    while not connected and retries > 0:
        try:
            consumer = KafkaConsumer(
                bootstrap_servers=BOOTSTRAP_SERVERS,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                key_deserializer=lambda k: k.decode("utf-8") if k else None,
                auto_offset_reset="latest",
                group_id="nf-debug-group",
                session_timeout_ms=10000
            )
            connected = True
        except NoBrokersAvailable:
            print(f"[!] No brokers available at {BOOTSTRAP_SERVERS}. Retrying in 5 seconds...")
            retries -= 1
            time.sleep(5)
            
    if not connected:
        print("[!] ERROR: Could not connect to Kafka cluster.")
        sys.exit(1)
        
    target_topics = [topic_filter] if topic_filter != "all" else TOPICS
    
    print(f"[*] Connected. Subscribing to topics: {', '.join(target_topics)}")
    consumer.subscribe(target_topics)
    
    print("-" * 50)
    print("Waiting for messages... (Press Ctrl+C to abort)")
    print("-" * 50)
    
    try:
        count = 0
        start = time.time()
        for msg in consumer:
            # Print minimal summary to avoid console flood during load tests
            ts = msg.timestamp if msg.timestamp else int(time.time() * 1000)
            
            # Identify core fields embedded by ingestion envelope
            v = msg.value
            tenant = v.get("tenant_id", "UNKNOWN_TENANT")
            sensor = v.get("sensor_id", "UNKNOWN_SENSOR")
            
            summary = f"[{msg.topic}]: Tenant='{tenant}' Sensor='{sensor}' MsgSizeBytes={len(str(v))}"
            
            if msg.topic == "nf.raw_packets":
                src = v.get("src_ip", "?")
                dst = v.get("dst_ip", "?")
                prt = v.get("protocol", "?")
                print(f"{summary} | {src} -> {dst} ({prt})")
            elif msg.topic == "nf.alerts":
                alert = v.get("severity", "?")
                engine = v.get("engine_name", "?")
                print(f"{summary} | ALERT: {alert} [{engine}]")
            else:
                print(f"{summary} | Keys: {list(v.keys())}")
                
            count += 1
            if count % 1000 == 0:
                elapsed = time.time() - start
                print(f"\n[>>>] Processed {count} messages... (Current Rate: {1000/elapsed:.2f} msg/sec)\n")
                start = time.time()
                
    except KeyboardInterrupt:
        print("\n[*] Stopped reading from Kafka.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetForensics Kafka Debug Consumer")
    parser.add_argument("--topic", type=str, default="all", help="Topic to listen to (or 'all')")
    args = parser.parse_args()
    
    main(args.topic)
