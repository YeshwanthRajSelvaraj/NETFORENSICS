import time
import json
import random
import requests
import argparse
import sys
from datetime import datetime, timezone
import concurrent.futures

INGEST_URL = "http://localhost:8080/api/v1/ingest/packets"

# Mock Auth token that our endpoint translates to 'org_test12'
TENANT_TOKEN = "test123456"

DOMAINS = ["google.com", "github.com", "malicious-c2.net", "windowsupdate.com", "api.slack.com"]
JA3_LIST = [
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0", # Chrome
    "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-119-49187-49191-118-49162-49172-57-49161-49171-51-157-156-61-60-53-47-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0", # Firefox
    "771,49191-49192-49199-49200-49171-49172-49187-49188-53-57-47-51,0-10-11-35,23-24-25,0", # Trickbot malware
]

def generate_random_ip():
    if random.random() > 0.5:
        # Generate internal generic IP
        return f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        # Generate varied external IP
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_packet_event() -> dict:
    """Generate a single normalized raw packet event."""
    ts = datetime.now(timezone.utc).timestamp()
    src_ip = generate_random_ip()
    dst_ip = generate_random_ip()
    
    # Randomly select a known application protocol profile
    profile = random.choice([
        {"proto": "TCP", "dst_port": 443, "size": random.randint(64, 1500), "ja3": random.choice(JA3_LIST)}, # HTTPS
        {"proto": "UDP", "dst_port": 53, "size": random.randint(64, 512), "dns": random.choice(DOMAINS)},    # DNS
        {"proto": "TCP", "dst_port": 80, "size": random.randint(64, 1500)},                                  # HTTP
        {"proto": "TCP", "dst_port": 22, "size": random.randint(64, 512)}                                    # SSH
    ])

    event = {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": profile["dst_port"],
        "protocol": profile["proto"],
        "size": profile["size"],
        "tcp_flags": "ACK,PSH" if profile["proto"] == "TCP" else None,
        "payload_entropy": round(random.uniform(3.0, 7.9), 2),
    }
    
    # Sneak in L7 metadata if present (to test parsing upstream in Kafka, even though this is the basic L3/L4 schema, 
    # the enterprise lake typically handles extra JSON keys using dynamic mapping if needed, or structured dropping)
    # Note: Our `nf.raw_packets` schema drops unknown fields, but let's test that dropping specifically 
    # by adding them here.
    if "ja3" in profile:
        event["tls_ja3"] = profile["ja3"]
    if "dns" in profile:
        event["dns_query"] = profile["dns"]

    return event


def send_batch(events: list):
    payload = {
        "sensor_id": "vpc-test-zone-1",
        "events": events
    }
    headers = {
        "Authorization": f"Bearer {TENANT_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        start = time.time()
        response = requests.post(INGEST_URL, json=payload, headers=headers, timeout=5)
        response.raise_for_status()
        elapsed = (time.time() - start) * 1000
        return len(events), elapsed
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Request Failed: {e}")
        return 0, 0


def run_load_test(events_per_sec: int, duration_sec: int, batch_size: int = 100):
    print(f"[*] Starting Load Test: {events_per_sec} events/sec for {duration_sec}s (Batch={batch_size})")
    print(f"[*] Target: {INGEST_URL}")
    print("-" * 50)
    
    total_events_sent = 0
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for second in range(duration_sec):
            sec_start = time.time()
            futures = []
            
            # Dispatch batches for the current second
            events_to_dispatch = events_per_sec
            while events_to_dispatch > 0:
                current_batch_size = min(batch_size, events_to_dispatch)
                batch = [generate_packet_event() for _ in range(current_batch_size)]
                futures.append(executor.submit(send_batch, batch))
                events_to_dispatch -= current_batch_size
            
            # Wait for all batches in this second to finish
            sec_sent = 0
            for future in concurrent.futures.as_completed(futures):
                sent, latency = future.result()
                sec_sent += sent
            
            total_events_sent += sec_sent
            
            # Pace the loop to exact seconds
            elapsed = time.time() - sec_start
            print(f"[>] Sec {second+1}/{duration_sec}: Sent {sec_sent} events in {elapsed*1000:.1f}ms")
            
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
                
    total_time = time.time() - start_time
    print("-" * 50)
    print(f"[*] Load Test Complete!")
    print(f"[*] Total Events Sent: {total_events_sent}")
    print(f"[*] Total Time: {total_time:.2f} seconds")
    print(f"[*] Effective Rate: {total_events_sent / total_time:.2f} events/sec")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetForensics Edge Sensor Simulator")
    parser.add_argument("--rate", type=int, default=10, help="Events per second to generate")
    parser.add_argument("--duration", type=int, default=10, help="Duration of the test in seconds")
    parser.add_argument("--batch", type=int, default=50, help="Batch size per HTTP request")
    
    args = parser.parse_args()
    
    # Verify the endpoint is alive before blasting it
    try:
        requests.get("http://localhost:8080/health", timeout=2)
    except:
        print("[!] ERROR: Ingestion Gateway at http://localhost:8080 is not reachable.")
        print("[!] Ensure you have started it via: 'python -m uvicorn app.main:app --port 8080'")
        sys.exit(1)
        
    run_load_test(events_per_sec=args.rate, duration_sec=args.duration, batch_size=args.batch)
