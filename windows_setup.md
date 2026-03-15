# NetForensics — Windows Compatibility Setup

Welcome to the newly refactored NetForensics Windows-compatible network capture and analysis engine!
We have completely migrated away from Linux-only `AF_PACKET` raw sockets and upgraded the engine to rely on the powerful `scapy` packet analysis framework running atop Npcap.

## Prerequisites

On Windows, standard networking sockets do **not** provide complete access to raw OSI Layer 2 interfaces. Therefore, we rely on **Npcap** (the Nmap packet capture library).

1. Download Npcap from: `https://npcap.com/`
2. Run the installer.
3. **CRITICAL STEP DURING INSTALLATION:** You **MUST** check the box that says **"Install Npcap in WinPcap API-compatible Mode"**. Scapy relies on this compatibility layer to interact with network interfaces on Windows.

## Dependency Installation

Once your driver is installed, open an Administrator PowerShell (or CMD) prompt, navigate to the `netforensics` repository root, and run:

```bash
pip install scapy pyshark psutil numpy pandas scikit-learn
```

*(Note: Although NetForensics is largely built using pure-Python statistical analysis to remain lightweight, features like the `ml_pipeline.py` may optionally utilize numpy, pandas, and scikit-learn for advanced dataset generation and offline training).*

## Running the Real-Time Demo

We have provided a ready-made hackathon-style script that demonstrates the platform's capabilities:

1. Open your terminal as Administrator (packet capture always requires elevated privileges).
2. Run the demo script:
   ```bash
   python run_capture.py
   ```
3. The script will automatically probe the OS and print all available Windows interfaces.
4. Type the index number of the interface you wish to sniff (e.g., your primary Wi-Fi or Ethernet adapter) and hit Enter.
5. Watch the alerts trigger! The real-time heuristic `TrafficAnalyzer` runs on an async queue every 5 seconds, logging discovered events directly to the console:
   - Command & Control Beaconing intervals
   - High-entropy volumetric exfiltration
   - Known threat actor TLS fingerprint matching (JA3 signatures)
   - Dynamic Tor exit node detection (fetches daily from TorProject's live lists) 

Happy hunting!
