<div align="center">
  <h1>🛡️ NetForensics</h1>
  <p><b>Advanced Encrypted Communications Metadata Analysis Platform</b></p>
  
  [![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
  [![React](https://img.shields.io/badge/React-18.0+-61DAFB.svg)](https://reactjs.org/)
  [![Docker](https://img.shields.io/badge/Docker-Supported-2496ED.svg)](https://www.docker.com/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
</div>

---

## 📖 Overview

**NetForensics** is a robust, lawful digital forensic tool designed to analyze network metadata without decrypting payloads. It empowers security operations centers (SOCs), incident responders, and forensic analysts to detect malicious activities, Command and Control (C2) beacons, data exfiltration, and network anomalies purely through traffic behavioral analysis.

Providing a hybrid approach akin to industry standards like Zeek and Darktrace, NetForensics offers deep visibility into encrypted communications using JA3 fingerprinting, flow clustering, and heuristic scorings.

---

## 🏗️ Architecture

```text
netforensics/
├── backend/
│   ├── capture/
│   │   └── packet_capture.py      Real AF_PACKET capture + PCAP import, TLS/JA3 dissector + DNS parser, Bidirectional flow tracker
│   ├── parsers/
│   │   └── ip_intel.py            IP classification, rDNS, reputation
│   ├── analysis/
│   │   └── traffic_analyzer.py    Beacon detection (CoV), burst detection, endpoint scoring, flow clustering
│   ├── correlation/
│   │   └── endpoint_correlator.py JA3 correlation, shared-destination, session similarity, repeated sessions
│   ├── api/
│   │   └── main.py                FastAPI + WebSocket (REST endpoints)
│   ├── database/
│   │   └── schema.sql             PostgreSQL production schema
│   ├── services/
│   │   └── demo_generator.py      Synthetic forensic scenario generator
│   └── requirements.txt
├── frontend/
│   └── src/
│       └── App.jsx                React dashboard (Recharts, SVG network graph, live feed)
├── scripts/
│   └── generate_demo.py           Standalone demo generator
├── docs/
├── docker-compose.yml
├── Dockerfile.backend
└── README.md
```

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

The fastest way to get NetForensics up and running is via Docker Compose.

```bash
git clone https://github.com/YeshwanthRajSelvaraj/NETFORENSICS.git
cd NETFORENSICS
docker-compose up --build
```
- **Backend API:** `http://localhost:8000`
- **Frontend Dashboard:** `http://localhost:3000`
- **API Documentation:** `http://localhost:8000/docs`

### Option 2: Manual Setup

**1. Backend:**
```bash
cd netforensics
pip install fastapi uvicorn[standard] aiosqlite python-multipart aiofiles

# Generate synthetic forensic data for demo purposes
python scripts/generate_demo.py

# Start the FastAPI server
python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```

**2. Frontend:**
```bash
cd frontend
npm install
npm run dev
# Dashboard available at http://localhost:3000
```

**3. Live Packet Capture (Linux, requires root):**
```bash
sudo python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000
# Initiate live capture via the dashboard UI
```

---

## 🧠 Analysis Modules

NetForensics encompasses multiple sophisticated detection engines:

| Module | Algorithm / Methodology | Output |
|---|---|---|
| **BeaconDetector** | Coefficient of Variation (CoV) on inter-arrival intervals | Regularity score (0–1), Confidence Level (HIGH/MEDIUM/LOW) |
| **BurstDetector** | 5s sliding window against session baselines (PPS) | Burst events categorized by severity |
| **EndpointScorer** | Multi-factor heuristic rule engine | Suspicion score (0–100) with supporting reasons |
| **FlowClusterer** | Rule-based behavioral correlation | Traffic clustering and behavioral labels |
| **TLSParser** | RFC-compliant ClientHello dissector | JA3 Hash, TLS version, SNI extraction |
| **DNSParser** | DNS packet decoding | Domain queries, Record types (A, CNAME, etc.) |

---

## 📡 API Reference

A fully documented OpenAPI interface is available at `/docs` when the backend is running. Core endpoints include:

| Method | Endpoint | Description |
|---|---|---|
| `GET`  | `/api/sessions` | Retrieve all capture sessions |
| `POST` | `/api/upload/pcap` | Ingest and process a PCAP file |
| `POST` | `/api/capture/start` | Initialize live network capture |
| `GET`  | `/api/sessions/{id}/flows` | Fetch paginated & filterable network flows |
| `GET`  | `/api/sessions/{id}/stats` | Retrieve protocol distributions, IP stats, & timelines |
| `GET`  | `/api/intel/ip/{ip}` | Query IP intelligence and reputation |
| `WS`   | `/ws` | Subscribe to real-time packet telemetry |

---

## 📊 Dashboard Modules

The React-based frontend provides deep investigative views:

- **Overview:** High-level metrics, protocol distributions, and top talkers.
- **Live Monitor:** Real-time WebSocket packet stream and rate histograms.
- **Flow Table:** Comprehensive flow records detailing JA3, SNI, and connection states.
- **Network Graph:** Interactive topology mapping nodes (IPs) and edges (flows).
- **Beacon Detection:** Automated C2 beacon identification and interval analysis.
- **TLS / JA3 Analysis:** Encrypted traffic profiling correlated with known threat signatures.

---

## 🦠 Malware JA3 Intelligence

NetForensics includes built-in detection for known malicious communication profiles:

| JA3 Hash | Associated Threat | Severity |
|---|---|---|
| `e7d705a3286e19ea42f587b344ee6865` | Cobalt Strike (Default) | **CRITICAL** |
| `6734f37431670b3ab4292b8f60f29984` | Metasploit Meterpreter | **CRITICAL** |
| `de9f2c7fd25e1b3afad3e85a0226823f` | TrickBot / Emotet | **CRITICAL** |
| `192a954d99b56e72cc6fcd974b862bb9` | AgentTesla Stealer | **HIGH** |

---

## ⚖️ Legal & Ethical Notice

**NetForensics** performs **metadata-only analysis** and does not decrypt or examine payload content. 
*Usage of this tool must be strictly limited to networks you own, operate, or have explicit, documented authorization to monitor.* It is designed for authorized security operations, incident response, and lawful digital forensics.

---

<div align="center">
  <i>Developed natively for advanced network threat hunting and metadata correlation.</i>
</div>
