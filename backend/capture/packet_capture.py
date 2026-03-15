"""
NetForensics — Packet Capture Module (Windows Compatible)
==========================================================
Real packet capture via Scapy (Npcap/WinPcap compatible).
Cross-platform support perfectly suited for Windows environments.
Features: Async queuing, Threading, JA3 fingerprinting, Flow aggregation.
"""

import hashlib
import logging
import math
import struct
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional
import queue
import asyncio

# Scapy imports
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNSQR, conf, get_if_list
from scapy.arch.windows import get_windows_if_list

logger = logging.getLogger("netforensics.capture")

# ─── Network Interface Listing for Windows ──────────────────────────────────
def get_windows_interfaces() -> List[str]:
    """Returns a list of available network interfaces."""
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        return [iface["name"] for iface in interfaces]
    except Exception:
        return get_if_list()

# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class PacketMeta:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str           # TCP / UDP / DNS / TLS / ICMP / OTHER
    size: int
    ttl: int
    flags: str              # SYN / ACK / FIN / RST / PSH
    flow_id: str
    tls_version: Optional[str] = None
    sni: Optional[str] = None
    ja3: Optional[str] = None
    ja3_string: Optional[str] = None
    cipher_suites: Optional[List[int]] = None
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None
    payload_entropy: Optional[float] = None

@dataclass
class FlowRecord:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    end_time: float
    packet_count: int = 0
    total_bytes: int = 0
    tls_version: Optional[str] = None
    sni: Optional[str] = None
    ja3: Optional[str] = None
    ja3_string: Optional[str] = None
    cipher_suites: Optional[List[int]] = None
    session_duration: float = 0.0
    avg_packet_size: float = 0.0
    packet_timestamps: List[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        try:
            d["start_time_iso"] = datetime.fromtimestamp(
                self.start_time, tz=timezone.utc).isoformat()
            d["end_time_iso"] = datetime.fromtimestamp(
                self.end_time, tz=timezone.utc).isoformat()
        except:
            d["start_time_iso"] = ""
            d["end_time_iso"] = ""
        return d

# ─── Entropy ─────────────────────────────────────────────────────────────────

def payload_entropy(data: bytes) -> float:
    """Shannon entropy. >=7.5 bits → likely encrypted."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return round(-sum((f / n) * math.log2(f / n) for f in freq if f > 0), 4)

# ─── TLS / JA3 ───────────────────────────────────────────────────────────────

class TLSParser:
    """
    TLS ClientHello dissector + JA3 fingerprint generator.
    Parses payload to extract SNI and JA3 parameters.
    """
    GREASE = frozenset({
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
        0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
        0xcaca, 0xdada, 0xeaea, 0xfafa,
    })
    VERSION_MAP = {
        0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
        0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
    }

    @classmethod
    def parse(cls, payload: bytes) -> Optional[dict]:
        try:
            if len(payload) < 9 or payload[0] != 0x16:
                return None
            rec_len = struct.unpack("!H", payload[3:5])[0]
            if len(payload) < 5 + rec_len:
                return None
            hs = payload[5:5 + rec_len]
            if hs[0] != 0x01: # 0x01 is ClientHello
                return None

            pos = 4
            hello_ver = struct.unpack("!H", hs[pos:pos + 2])[0]
            pos += 2 + 32  # version + random

            sid_len = hs[pos]; pos += 1 + sid_len

            cs_len = struct.unpack("!H", hs[pos:pos + 2])[0]; pos += 2
            ciphers = []
            for i in range(0, cs_len, 2):
                c = struct.unpack("!H", hs[pos + i:pos + i + 2])[0]
                if c not in cls.GREASE:
                    ciphers.append(c)
            pos += cs_len

            comp_len = hs[pos]; pos += 1 + comp_len

            if pos + 2 > len(hs):
                return cls._result(hello_ver, ciphers, [], [], [], None)

            ext_total = struct.unpack("!H", hs[pos:pos + 2])[0]; pos += 2
            exts, groups, pt_fmts = [], [], []
            sni = None
            end = pos + ext_total

            while pos + 4 <= end and pos + 4 <= len(hs):
                etype = struct.unpack("!H", hs[pos:pos + 2])[0]
                elen  = struct.unpack("!H", hs[pos + 2:pos + 4])[0]
                edata = hs[pos + 4:pos + 4 + elen]
                pos  += 4 + elen

                if etype not in cls.GREASE:
                    exts.append(etype)

                if etype == 0 and len(edata) > 5:          # SNI
                    try:
                        nl = struct.unpack("!H", edata[3:5])[0]
                        sni = edata[5:5 + nl].decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                elif etype == 0x0a and len(edata) >= 2:    # Supported Groups
                    gl = struct.unpack("!H", edata[0:2])[0]
                    for i in range(0, gl, 2):
                        g = struct.unpack("!H", edata[2 + i:4 + i])[0]
                        if g not in cls.GREASE:
                            groups.append(g)
                elif etype == 0x0b and len(edata) >= 1:    # EC Point Formats
                    pt_fmts = list(edata[1:1 + edata[0]])

            return cls._result(hello_ver, ciphers, exts, groups, pt_fmts, sni)
        except Exception as e:
            return None

    @classmethod
    def _result(cls, ver, ciphers, exts, groups, pt_fmts, sni):
        s = ",".join([str(ver),
                      "-".join(map(str, ciphers)),
                      "-".join(map(str, exts)),
                      "-".join(map(str, groups)),
                      "-".join(map(str, pt_fmts))])
        return {
            "tls_version":   cls.VERSION_MAP.get(ver, f"0x{ver:04x}"),
            "sni":           sni,
            "cipher_suites": ciphers,
            "extensions":    exts,
            "ja3":           hashlib.md5(s.encode()).hexdigest(),
            "ja3_string":    s,
        }

# ─── DNS ─────────────────────────────────────────────────────────────────────

class DNSParser:
    QTYPE = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA",
             15:"MX", 16:"TXT", 28:"AAAA", 255:"ANY"}

# ─── Flow Tracker ─────────────────────────────────────────────────────────────

class FlowTracker:
    """Thread-safe bidirectional flow aggregator."""
    TIMEOUT = 120   # seconds

    def __init__(self):
        self._flows: Dict[str, FlowRecord] = {}
        self._lock  = threading.Lock()

    @staticmethod
    def make_id(src_ip, dst_ip, src_port, dst_port, protocol) -> str:
        pair = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        raw  = f"{pair[0][0]}:{pair[0][1]}-{pair[1][0]}:{pair[1][1]}-{protocol}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def update(self, pkt: PacketMeta) -> FlowRecord:
        with self._lock:
            flow = self._flows.get(pkt.flow_id)
            if flow is None:
                flow = FlowRecord(
                    flow_id=pkt.flow_id,
                    src_ip=pkt.src_ip,   dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port, dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    start_time=pkt.timestamp, end_time=pkt.timestamp,
                )
                self._flows[pkt.flow_id] = flow

            flow.packet_count   += 1
            flow.total_bytes    += pkt.size
            flow.end_time        = pkt.timestamp
            flow.session_duration = max(0, flow.end_time - flow.start_time)
            flow.avg_packet_size  = flow.total_bytes / flow.packet_count
            flow.packet_timestamps.append(pkt.timestamp)

            if pkt.tls_version:    flow.tls_version   = pkt.tls_version
            if pkt.sni:            flow.sni            = pkt.sni
            if pkt.ja3:            flow.ja3            = pkt.ja3
            if pkt.ja3_string:     flow.ja3_string     = pkt.ja3_string
            if pkt.cipher_suites:  flow.cipher_suites  = pkt.cipher_suites
            return flow

    def snapshot(self) -> List[FlowRecord]:
        with self._lock:
            return list(self._flows.values())

    def __len__(self):
        return len(self._flows)


# ─── Scapy Windows Packet Capture ──────────────────────────────────────────────

class RawSocketCapture:
    """
    Windows-native Packet Capture Engine using Scapy.
    Replacing the legacy Linux AF_PACKET raw socket implementation.
    """
    TLS_PORTS  = frozenset({443, 8443, 465, 993, 995, 8080, 8888})

    def __init__(self, interface: str = "any"):
        self.interface    = None if interface == "any" else interface
        self.running      = False
        self.flow_tracker = FlowTracker()
        self._callbacks: List[Callable] = []

    def add_callback(self, fn: Callable) -> None:
        self._callbacks.append(fn)

    def _emit(self, pkt: PacketMeta) -> None:
        for cb in self._callbacks:
            try:
                cb(pkt)
            except Exception as e:
                logger.error("Callback error: %s", e)

    def _scapy_packet_handler(self, p):
        ts = float(p.time)
        
        if not p.haslayer(IP) and not p.haslayer(IPv6):
            return 
            
        ip_layer = p[IP] if p.haslayer(IP) else p[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = ip_layer.ttl if p.haslayer(IP) else ip_layer.hlim
        size = len(p)
        
        src_port = dst_port = 0
        proto = "OTHER"
        flags_str = ""
        tls_info = None
        dns_res = None
        payload = b""
        
        if p.haslayer(TCP):
            proto = "TCP"
            src_port = p[TCP].sport
            dst_port = p[TCP].dport
            flags_str = str(p[TCP].flags)
            
            import scapy.packet
            if p.haslayer(scapy.packet.Raw):
                payload = bytes(p[scapy.packet.Raw].load)
            
            if src_port in self.TLS_PORTS or dst_port in self.TLS_PORTS:
                if payload:
                    tls_info = TLSParser.parse(payload)
                    if tls_info:
                        proto = "TLS"
        elif p.haslayer(UDP):
            proto = "UDP"
            src_port = p[UDP].sport
            dst_port = p[UDP].dport
            
            import scapy.packet
            if p.haslayer(scapy.packet.Raw):
                payload = bytes(p[scapy.packet.Raw].load)
                
            if p.haslayer(DNSQR):
                proto = "DNS"
                try:
                    qname = p[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    qtype = DNSParser.QTYPE.get(p[DNSQR].qtype, str(p[DNSQR].qtype))
                    dns_res = (qname, qtype)
                except:
                    pass
        elif p.haslayer(ICMP):
            proto = "ICMP"
            
        fid = FlowTracker.make_id(src_ip, dst_ip, src_port, dst_port, proto)
        
        pkt = PacketMeta(
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, protocol=proto,
            size=size, ttl=ttl, flags=flags_str, flow_id=fid,
            tls_version  = tls_info.get("tls_version")   if tls_info else None,
            sni          = tls_info.get("sni")            if tls_info else None,
            ja3          = tls_info.get("ja3")            if tls_info else None,
            ja3_string   = tls_info.get("ja3_string")     if tls_info else None,
            cipher_suites= tls_info.get("cipher_suites")  if tls_info else None,
            dns_query    = dns_res[0] if dns_res else None,
            dns_type     = dns_res[1] if dns_res else None,
            payload_entropy = payload_entropy(payload[:256]) if payload else None,
        )
        self.flow_tracker.update(pkt)
        self._emit(pkt)

    def start_live(self) -> None:
        self.running = True
        logger.info(f"Live capture started on interface (Windows Compatible): {self.interface or 'all'}")
        try:
            # Import raw specifically for payload extraction
            import scapy.packet
            globals()['scapy'] = __import__('scapy')
            sniff(iface=self.interface, prn=self._scapy_packet_handler, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            logger.critical(f"Sniffing error (Did you install Npcap Windows compatibility?): {e}")
            raise

    def stop(self) -> None:
        self.running = False


# ─── PCAP Importer ───────────────────────────────────────────────────────────

class PcapImporter:
    """Offline PCAP processing using Scapy."""
    def __init__(self, path: str):
        self.path         = Path(path)
        self.flow_tracker = FlowTracker()
        self._cap         = RawSocketCapture()
        self._cap.flow_tracker = self.flow_tracker
        self.packets      = []
        self._cap.add_callback(self.packets.append)

    def parse(self) -> List[PacketMeta]:
        try:
            import scapy.packet
            globals()['scapy'] = __import__('scapy')
            from scapy.all import rdpcap
            logger.info("Importing PCAP: %s", self.path)
            sniff(offline=str(self.path), prn=self._cap._scapy_packet_handler, store=0)
        except Exception as e:
            logger.error("PCAP import error: %s", e)
            
        logger.info("PCAP imported %d packets, %d flows.", len(self.packets), len(self.flow_tracker))
        return self.packets

    def flows(self) -> List[FlowRecord]:
        return self.flow_tracker.snapshot()
