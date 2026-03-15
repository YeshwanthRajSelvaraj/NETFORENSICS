import sys
import os
import time
import logging
import threading
import queue

# Adjust path if running directly
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.capture.packet_capture import get_windows_interfaces, RawSocketCapture
from backend.analysis.traffic_analyzer import TrafficAnalyzer
from backend.analysis.ml_threat_detector import MLThreatDetector

# Setup basic logging to console
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("demo")

def main():
    print("="*60)
    print("NetForensics Windows Capable PCAP & Threat Demo")
    print("="*60)
    
    # 1. List Interfaces
    interfaces = get_windows_interfaces()
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
        
    print("\nSelect an interface to capture from (enter number, or 'any' for all): ")
    sel = input("> ").strip()
    
    if sel.lower() == 'any':
        selected_iface = "any"
    else:
        try:
            selected_iface = interfaces[int(sel)]
        except (ValueError, IndexError):
            print("Invalid selection. Exiting.")
            return

    print(f"\n[+] Selected interface: {selected_iface}")
    
    # 2. Setup Analysis Engines
    print("[+] Initializing Threat Analysis Engine...")
    traffic_analyzer = TrafficAnalyzer()
    
    # Optional: We could initialize ML Pipeline here if models exist
    # ml_detector = MLThreatDetector()
    # ml_detector.initialize(...)
    
    # 3. Setup Capture Engine
    print("[+] Starting Scapy Packet Capture...")
    cap = RawSocketCapture(interface=selected_iface)
    
    # Async Queue for processing packets
    packet_queue = queue.Queue()
    
    def packet_handler(pkt):
        packet_queue.put(pkt)
        
    cap.add_callback(packet_handler)
    
    # 4. Processing Thread
    def log_threats():
        last_analysis = time.time()
        flows_buffer = []
        pkts_buffer = []
        
        while cap.running or not packet_queue.empty():
            try:
                pkt = packet_queue.get(timeout=1.0)
                pkts_buffer.append(pkt.__dict__)
            except queue.Empty:
                pass
                
            # Perform heuristic analysis every 5 seconds on recent packets
            if time.time() - last_analysis > 5.0 and pkts_buffer:
                # Get current flows
                current_flows = [f.to_dict() for f in cap.flow_tracker.snapshot()]
                
                try:
                    # Run heuristic analysis
                    results = traffic_analyzer.analyse(current_flows, pkts_buffer)
                    
                    # Print found threats
                    if results.get("beacons"):
                        print(f"\n[🚨 ALERT] Detected {len(results['beacons'])} Beaconing C2 Channels!")
                        for b in results["beacons"]:
                            print(f"   -> {b['src_ip']} -> {b['dst_ip']} (Interval: {b['interval_mean']:.1f}s, Conf: {b['confidence']})")
                            
                    if results.get("bursts"):
                        print(f"\n[🚨 ALERT] Detected {len(results['bursts'])} volumetric burst anomalies!")
                        
                    if results.get("suspicious_ips"):
                        for ip_data in results["suspicious_ips"]:
                            if ip_data["suspicion_score"] > 30:
                                print(f"\n[🚨 ALERT] Suspicious IP: {ip_data['ip']} (Score: {ip_data['suspicion_score']})")
                                for r in ip_data["reasons"]:
                                    print(f"   - {r}")
                except Exception as e:
                    logger.error(f"Analysis iteration failed: {e}")
                    
                # reset buffer
                pkts_buffer = []
                last_analysis = time.time()

    t_processing = threading.Thread(target=log_threats, daemon=True)
    t_processing.start()

    # 5. Start Blocking Capture
    try:
        cap.start_live()
    except KeyboardInterrupt:
        print("\nStopping capture...")
        cap.stop()

    t_processing.join(timeout=2.0)
    print("Demo execution finished.")

if __name__ == "__main__":
    main()
