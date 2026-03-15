"""
NetForensics — Network Graph AI Engine v5
===========================================
AI/ML-powered network graph analysis for:

  MODULE 1: InfrastructureClusterer  — Graph community detection + attacker infra grouping
  MODULE 2: GraphAnomalyDetector    — Structural anomalies (hub-spoke, clique, star topologies)
  MODULE 3: CommunicationProfiler   — Per-IP communication pattern classification
  MODULE 4: C2InfraMapper           — Automated C2 infrastructure mapping via graph centrality

Uses pure Python graph algorithms (no external ML libraries required).

MITRE ATT&CK: T1071 (App Layer Protocol), T1090 (Proxy), T1105 (Ingress Tool Transfer)
"""

import hashlib
import logging
import math
import statistics
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("netforensics.graph_ai")


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class InfrastructureCluster:
    """Detected attacker infrastructure cluster."""
    cluster_id: str
    name: str
    node_count: int
    edge_count: int
    nodes: List[str]             # IP addresses in cluster
    hub_ip: str                  # Most connected node
    total_bytes: int
    total_flows: int
    avg_degree: float
    density: float               # Edge density within cluster
    threat_score: float          # 0-100
    classification: str          # "c2_infrastructure", "botnet", "lateral_movement",
                                 # "data_staging", "scan_network", "normal"
    evidence: List[str]
    mitre_techniques: List[str]


@dataclass
class GraphAnomaly:
    """Structural anomaly in the network graph."""
    anomaly_type: str            # "hub_spoke", "clique", "star", "isolated_heavy",
                                 # "asymmetric", "rapid_expansion"
    severity: str
    score: float
    involved_ips: List[str]
    evidence: List[str]
    mitre_technique: str = ""


@dataclass
class CommunicationProfile:
    """Per-IP communication pattern classification."""
    ip: str
    profile_type: str            # "workstation", "server", "scanner", "proxy",
                                 # "c2_client", "c2_server", "data_mover", "sleeper"
    confidence: float
    in_degree: int               # unique sources connecting to this IP
    out_degree: int              # unique destinations from this IP
    total_degree: int
    betweenness: float           # betweenness centrality
    pagerank: float              # PageRank score
    clustering_coefficient: float
    evidence: List[str]


# ═══════════════════════════════════════════════════════════════════════════════
# GRAPH DATA STRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkGraph:
    """Adjacency list graph with weighted edges for network analysis."""

    def __init__(self):
        self._adj: Dict[str, Dict[str, Dict]] = defaultdict(dict)
        self._in_degree: Dict[str, int] = defaultdict(int)
        self._out_degree: Dict[str, int] = defaultdict(int)
        self._node_data: Dict[str, Dict] = defaultdict(dict)

    def add_edge(self, src: str, dst: str, weight: float = 1.0,
                 flows: int = 1, protocol: str = ""):
        if dst in self._adj[src]:
            self._adj[src][dst]["weight"] += weight
            self._adj[src][dst]["flows"] += flows
        else:
            self._adj[src][dst] = {"weight": weight, "flows": flows,
                                    "protocol": protocol}
            self._out_degree[src] += 1
            self._in_degree[dst] += 1
        # Ensure node exists
        if src not in self._node_data: self._node_data[src] = {}
        if dst not in self._node_data: self._node_data[dst] = {}

    @property
    def nodes(self) -> Set[str]:
        return set(self._node_data.keys())

    @property
    def node_count(self) -> int:
        return len(self._node_data)

    @property
    def edge_count(self) -> int:
        return sum(len(neighbors) for neighbors in self._adj.values())

    def neighbors(self, node: str) -> Dict[str, Dict]:
        return self._adj.get(node, {})

    def in_neighbors(self, node: str) -> List[str]:
        return [src for src, nbrs in self._adj.items() if node in nbrs]

    def degree(self, node: str) -> int:
        return self._out_degree.get(node, 0) + self._in_degree.get(node, 0)

    def out_degree(self, node: str) -> int:
        return self._out_degree.get(node, 0)

    def in_degree(self, node: str) -> int:
        return self._in_degree.get(node, 0)

    def edge_weight(self, src: str, dst: str) -> float:
        return self._adj.get(src, {}).get(dst, {}).get("weight", 0)

    def total_weight(self, node: str) -> float:
        return sum(e["weight"] for e in self._adj.get(node, {}).values())

    @classmethod
    def from_flows(cls, flows: List[dict]) -> "NetworkGraph":
        g = cls()
        for f in flows:
            src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
            if src and dst:
                g.add_edge(src, dst,
                          weight=f.get("total_bytes", 0),
                          flows=1,
                          protocol=f.get("protocol", ""))
        return g


# ═══════════════════════════════════════════════════════════════════════════════
# GRAPH ALGORITHMS
# ═══════════════════════════════════════════════════════════════════════════════

def _pagerank(graph: NetworkGraph, damping: float = 0.85,
              iterations: int = 30) -> Dict[str, float]:
    """Simplified PageRank for network centrality."""
    n = graph.node_count
    if n == 0:
        return {}
    nodes = list(graph.nodes)
    pr = {node: 1.0 / n for node in nodes}

    for _ in range(iterations):
        new_pr = {}
        for node in nodes:
            rank_sum = 0.0
            for src in graph.in_neighbors(node):
                out = graph.out_degree(src)
                if out > 0:
                    rank_sum += pr.get(src, 0) / out
            new_pr[node] = (1 - damping) / n + damping * rank_sum
        pr = new_pr

    return pr


def _betweenness_centrality(graph: NetworkGraph, sample: int = 50) -> Dict[str, float]:
    """Approximate betweenness centrality via BFS sampling."""
    nodes = list(graph.nodes)
    bc = {n: 0.0 for n in nodes}
    sample_nodes = nodes[:min(sample, len(nodes))]

    for s in sample_nodes:
        # BFS from s
        dist = {s: 0}
        pred: Dict[str, List[str]] = defaultdict(list)
        sigma = defaultdict(int)
        sigma[s] = 1
        queue = deque([s])
        stack = []

        while queue:
            v = queue.popleft()
            stack.append(v)
            for w in graph.neighbors(v):
                if w not in dist:
                    dist[w] = dist[v] + 1
                    queue.append(w)
                if dist.get(w, -1) == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        delta = defaultdict(float)
        while stack:
            w = stack.pop()
            for v in pred[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != s:
                bc[w] += delta[w]

    # Normalize
    n = len(nodes)
    if n > 2:
        norm = 2.0 / ((n - 1) * (n - 2))
        for node in bc:
            bc[node] *= norm

    return bc


def _clustering_coefficient(graph: NetworkGraph, node: str) -> float:
    """Local clustering coefficient: fraction of neighbor pairs that are connected."""
    nbrs = set(graph.neighbors(node).keys())
    k = len(nbrs)
    if k < 2:
        return 0.0
    links = 0
    for u in nbrs:
        for v in nbrs:
            if u != v and v in graph.neighbors(u):
                links += 1
    return links / (k * (k - 1))


def _label_propagation_communities(graph: NetworkGraph) -> Dict[str, int]:
    """Simple label propagation for community detection."""
    import random
    nodes = list(graph.nodes)
    labels = {n: i for i, n in enumerate(nodes)}

    for _ in range(20):  # iterations
        random.shuffle(nodes)
        changed = False
        for node in nodes:
            neighbor_labels = []
            for nbr in graph.neighbors(node):
                neighbor_labels.append(labels.get(nbr, 0))
            for src in graph.in_neighbors(node):
                neighbor_labels.append(labels.get(src, 0))

            if neighbor_labels:
                most_common = Counter(neighbor_labels).most_common(1)[0][0]
                if labels[node] != most_common:
                    labels[node] = most_common
                    changed = True
        if not changed:
            break

    return labels


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: INFRASTRUCTURE CLUSTERER
# ═══════════════════════════════════════════════════════════════════════════════

class InfrastructureClusterer:
    """
    Detect attacker infrastructure clusters using graph community detection.
    Groups IPs that form suspicious communication patterns.
    """

    def analyse(self, graph: NetworkGraph, suspicious_ips: Set[str] = None) -> List[InfrastructureCluster]:
        suspicious_ips = suspicious_ips or set()

        # Run community detection
        communities = _label_propagation_communities(graph)

        # Group nodes by community
        comm_nodes: Dict[int, List[str]] = defaultdict(list)
        for node, comm_id in communities.items():
            comm_nodes[comm_id].append(node)

        clusters = []
        for comm_id, nodes in comm_nodes.items():
            if len(nodes) < 3:
                continue

            # Compute cluster metrics
            internal_edges = 0
            total_bytes = 0
            total_flows = 0
            node_set = set(nodes)

            for src in nodes:
                for dst, edge in graph.neighbors(src).items():
                    if dst in node_set:
                        internal_edges += 1
                        total_bytes += edge["weight"]
                        total_flows += edge["flows"]

            max_edges = len(nodes) * (len(nodes) - 1)
            density = internal_edges / max_edges if max_edges > 0 else 0
            avg_degree = sum(graph.degree(n) for n in nodes) / len(nodes)

            # Find hub
            hub = max(nodes, key=lambda n: graph.degree(n))

            # Classify cluster
            susp_count = sum(1 for n in nodes if n in suspicious_ips)
            susp_ratio = susp_count / len(nodes)

            classification, evidence, score, mitre = self._classify_cluster(
                nodes, hub, density, avg_degree, total_bytes, susp_ratio, graph)

            cluster_id = hashlib.md5("|".join(sorted(nodes)).encode()).hexdigest()[:10]

            clusters.append(InfrastructureCluster(
                cluster_id=cluster_id,
                name=f"{classification.replace('_', ' ').title()} — {hub}",
                node_count=len(nodes),
                edge_count=internal_edges,
                nodes=nodes[:30],
                hub_ip=hub,
                total_bytes=total_bytes,
                total_flows=total_flows,
                avg_degree=round(avg_degree, 2),
                density=round(density, 4),
                threat_score=score,
                classification=classification,
                evidence=evidence,
                mitre_techniques=mitre,
            ))

        return sorted(clusters, key=lambda c: c.threat_score, reverse=True)[:20]

    def _classify_cluster(self, nodes, hub, density, avg_degree,
                          total_bytes, susp_ratio, graph) -> Tuple[str, List[str], float, List[str]]:
        evidence = []
        score = 0.0
        mitre = []

        hub_out = graph.out_degree(hub)
        hub_in = graph.in_degree(hub)

        # Hub-spoke pattern → C2 infrastructure
        if hub_out > len(nodes) * 0.4 and density < 0.3:
            score += 30
            evidence.append(f"Hub-spoke pattern: {hub} connects to {hub_out} nodes")
            mitre.append("T1071")
            classification = "c2_infrastructure"
        # Dense clique → botnet or lateral movement
        elif density > 0.5 and len(nodes) > 4:
            score += 25
            evidence.append(f"Dense mesh: {density:.0%} connectivity")
            mitre.append("T1021")
            classification = "lateral_movement" if susp_ratio > 0.3 else "normal"
        # Star topology → scanning
        elif hub_out > 10 and avg_degree < 2:
            score += 20
            evidence.append(f"Star topology: {hub} scanning {hub_out} targets")
            mitre.append("T1046")
            classification = "scan_network"
        # Data staging
        elif total_bytes > 50_000_000 and hub_in > len(nodes) * 0.3:
            score += 25
            evidence.append(f"Data staging: {total_bytes / 1e6:.1f}MB via {hub}")
            mitre.append("T1074")
            classification = "data_staging"
        else:
            classification = "normal"

        # Suspicious IP bonus
        if susp_ratio > 0.5:
            score += 20
            evidence.append(f"{susp_ratio:.0%} of nodes flagged suspicious")
        elif susp_ratio > 0.2:
            score += 10

        # Size bonus
        if len(nodes) > 10:
            score += 10
            evidence.append(f"Large cluster: {len(nodes)} nodes")

        score = min(100, score)
        return classification, evidence, score, mitre


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: GRAPH ANOMALY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class GraphAnomalyDetector:
    """Detect structural anomalies in the communication graph."""

    def analyse(self, graph: NetworkGraph) -> List[GraphAnomaly]:
        anomalies = []
        nodes = list(graph.nodes)
        if len(nodes) < 5:
            return anomalies

        degrees = {n: graph.degree(n) for n in nodes}
        if not degrees:
            return anomalies

        mean_deg = statistics.mean(degrees.values())
        std_deg = statistics.stdev(degrees.values()) if len(degrees) > 1 else 0

        # 1. Hub nodes (degree >> mean)
        for node in nodes:
            d = degrees[node]
            if std_deg > 0 and (d - mean_deg) / std_deg > 3:
                anomalies.append(GraphAnomaly(
                    anomaly_type="hub_node",
                    severity="HIGH" if d > mean_deg * 5 else "MEDIUM",
                    score=min(85, 40 + d // 2),
                    involved_ips=[node],
                    evidence=[f"Hub: {node} degree={d} (mean={mean_deg:.1f}, "
                             f"z-score={(d - mean_deg) / std_deg:.1f})"],
                    mitre_technique="T1090",
                ))

        # 2. Asymmetric traffic (large outbound, tiny inbound)
        for node in nodes:
            out_w = graph.total_weight(node)
            in_w = sum(graph.edge_weight(src, node) for src in graph.in_neighbors(node))
            if out_w > 10_000_000 and in_w > 0 and out_w / in_w > 20:
                anomalies.append(GraphAnomaly(
                    anomaly_type="asymmetric_traffic",
                    severity="HIGH",
                    score=min(80, 50 + int(math.log2(out_w / in_w))),
                    involved_ips=[node],
                    evidence=[f"Asymmetric: {node} sent {out_w / 1e6:.1f}MB, "
                             f"received {in_w / 1e6:.1f}MB (ratio: {out_w / in_w:.0f}x)"],
                    mitre_technique="T1041",
                ))

        # 3. Isolated heavy edges (two nodes exchanging massive data)
        for src in nodes:
            for dst, edge in graph.neighbors(src).items():
                if edge["weight"] > 50_000_000 and degrees[src] <= 3:
                    anomalies.append(GraphAnomaly(
                        anomaly_type="isolated_heavy_edge",
                        severity="HIGH",
                        score=min(75, 40 + int(edge["weight"] / 10_000_000)),
                        involved_ips=[src, dst],
                        evidence=[f"Isolated heavy transfer: {src}→{dst} "
                                 f"{edge['weight'] / 1e6:.1f}MB, low degree={degrees[src]}"],
                        mitre_technique="T1048",
                    ))

        return sorted(anomalies, key=lambda a: a.score, reverse=True)[:30]


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: COMMUNICATION PROFILER
# ═══════════════════════════════════════════════════════════════════════════════

class CommunicationProfiler:
    """Classify each IP's communication pattern using graph metrics."""

    def analyse(self, graph: NetworkGraph) -> List[CommunicationProfile]:
        if graph.node_count < 3:
            return []

        pr = _pagerank(graph)
        bc = _betweenness_centrality(graph)
        profiles = []

        for node in graph.nodes:
            in_deg = graph.in_degree(node)
            out_deg = graph.out_degree(node)
            total = in_deg + out_deg
            betw = bc.get(node, 0)
            prank = pr.get(node, 0)
            cc = _clustering_coefficient(graph, node)

            profile_type, confidence, evidence = self._classify(
                node, in_deg, out_deg, total, betw, prank, cc, graph)

            profiles.append(CommunicationProfile(
                ip=node,
                profile_type=profile_type,
                confidence=confidence,
                in_degree=in_deg,
                out_degree=out_deg,
                total_degree=total,
                betweenness=round(betw, 6),
                pagerank=round(prank, 6),
                clustering_coefficient=round(cc, 4),
                evidence=evidence,
            ))

        return sorted(profiles, key=lambda p: p.betweenness, reverse=True)

    def _classify(self, node, in_deg, out_deg, total, betw, prank, cc,
                  graph) -> Tuple[str, float, List[str]]:
        evidence = []
        is_internal = node.startswith(("10.", "192.168.", "172."))

        # C2 server: high in-degree, low out-degree, external
        if not is_internal and in_deg > 5 and out_deg <= 2:
            return "c2_server", 0.7, [f"External with {in_deg} inbound, {out_deg} outbound"]

        # C2 client: single persistent external destination
        if is_internal and out_deg == 1 and total > 5:
            dst = list(graph.neighbors(node).keys())[0] if graph.neighbors(node) else ""
            if dst and not dst.startswith(("10.", "192.168.", "172.")):
                return "c2_client", 0.6, [f"Single external destination: {dst}"]

        # Scanner: high out-degree, many short connections
        if out_deg > 20 and in_deg < out_deg * 0.1:
            return "scanner", 0.8, [f"Fan-out: {out_deg} destinations, {in_deg} sources"]

        # Proxy/relay: high betweenness, connects communities
        if betw > 0.1 and total > 5:
            return "proxy", 0.65, [f"Betweenness: {betw:.4f} (bridge node)"]

        # Data mover: asymmetric heavy traffic
        out_w = graph.total_weight(node)
        if out_w > 10_000_000:
            return "data_mover", 0.6, [f"Moved {out_w / 1e6:.1f}MB outbound"]

        # Server: high in-degree
        if in_deg > 10 and is_internal:
            return "server", 0.75, [f"Server pattern: {in_deg} inbound connections"]

        # Workstation (default)
        return "workstation", 0.5, [f"Standard: in={in_deg}, out={out_deg}"]


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4: C2 INFRASTRUCTURE MAPPER
# ═══════════════════════════════════════════════════════════════════════════════

class C2InfraMapper:
    """
    Map C2 infrastructure using graph centrality and traffic patterns.
    Identifies potential C2 servers, staging points, and redirectors.
    """

    def analyse(self, graph: NetworkGraph, beacons: List[dict] = None,
                suspicious_ips: Set[str] = None) -> Dict:
        beacons = beacons or []
        suspicious_ips = suspicious_ips or set()

        pr = _pagerank(graph)
        bc = _betweenness_centrality(graph)

        c2_candidates = []
        beacon_dsts = {b.get("dst_ip", "") for b in beacons}
        beacon_srcs = {b.get("src_ip", "") for b in beacons}

        for node in graph.nodes:
            if node.startswith(("10.", "192.168.", "172.")):
                continue  # Skip internal
            in_deg = graph.in_degree(node)
            score = 0
            evidence = []

            # Multiple internal clients connecting → possible C2
            internal_clients = [src for src in graph.in_neighbors(node)
                               if src.startswith(("10.", "192.168.", "172."))]
            if len(internal_clients) > 2:
                score += 20
                evidence.append(f"{len(internal_clients)} internal clients")

            # Known beacon destination
            if node in beacon_dsts:
                score += 25
                evidence.append("Beacon destination")

            # High PageRank for external node
            if pr.get(node, 0) > 0.05:
                score += 15
                evidence.append(f"PageRank: {pr[node]:.4f}")

            # In suspicious IP list
            if node in suspicious_ips:
                score += 15
                evidence.append("Flagged suspicious")

            # High betweenness (redirector)
            if bc.get(node, 0) > 0.05:
                score += 10
                evidence.append(f"Betweenness: {bc[node]:.4f} (potential redirector)")

            if score > 20:
                c2_candidates.append({
                    "ip": node,
                    "c2_score": min(100, score),
                    "role": "c2_server" if in_deg > 3 else
                            "redirector" if bc.get(node, 0) > 0.05 else "staging",
                    "internal_clients": internal_clients[:10],
                    "pagerank": round(pr.get(node, 0), 6),
                    "betweenness": round(bc.get(node, 0), 6),
                    "evidence": evidence,
                })

        # Build infrastructure map
        infra_map = {
            "c2_servers": [c for c in c2_candidates if c["role"] == "c2_server"],
            "redirectors": [c for c in c2_candidates if c["role"] == "redirector"],
            "staging_points": [c for c in c2_candidates if c["role"] == "staging"],
            "compromised_clients": sorted(beacon_srcs)[:30],
        }

        return {
            "c2_candidates": sorted(c2_candidates, key=lambda c: c["c2_score"], reverse=True)[:20],
            "infrastructure_map": infra_map,
            "summary": {
                "c2_servers": len(infra_map["c2_servers"]),
                "redirectors": len(infra_map["redirectors"]),
                "staging_points": len(infra_map["staging_points"]),
                "compromised_clients": len(infra_map["compromised_clients"]),
                "total_candidates": len(c2_candidates),
            },
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MASTER NETWORK GRAPH AI ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkGraphAI:
    """
    Orchestrates all graph-based AI analysis modules.
    Builds the network graph and runs community detection, anomaly detection,
    profiling, and C2 mapping.
    """

    def __init__(self):
        self.clusterer = InfrastructureClusterer()
        self.anomaly_detector = GraphAnomalyDetector()
        self.profiler = CommunicationProfiler()
        self.c2_mapper = C2InfraMapper()

    def analyse(self, flows: List[dict], beacons: List[dict] = None,
                suspicious_ips: Set[str] = None) -> Dict:
        """Run full graph AI analysis."""
        beacons = beacons or []
        suspicious_ips = suspicious_ips or set()

        # Build graph
        graph = NetworkGraph.from_flows(flows)
        if graph.node_count < 3:
            return {"error": "Insufficient nodes for graph analysis",
                    "node_count": graph.node_count}

        # Run all modules
        clusters = self.clusterer.analyse(graph, suspicious_ips)
        anomalies = self.anomaly_detector.analyse(graph)
        profiles = self.profiler.analyse(graph)
        c2_map = self.c2_mapper.analyse(graph, beacons, suspicious_ips)

        # Per-IP risk from graph
        pr = _pagerank(graph)

        return {
            "infrastructure_clusters": [
                {"id": c.cluster_id, "name": c.name, "classification": c.classification,
                 "node_count": c.node_count, "edge_count": c.edge_count,
                 "hub_ip": c.hub_ip, "density": c.density,
                 "threat_score": c.threat_score, "evidence": c.evidence,
                 "mitre": c.mitre_techniques, "nodes": c.nodes[:15]}
                for c in clusters
            ],
            "graph_anomalies": [
                {"type": a.anomaly_type, "severity": a.severity,
                 "score": a.score, "ips": a.involved_ips,
                 "evidence": a.evidence, "mitre": a.mitre_technique}
                for a in anomalies
            ],
            "communication_profiles": [
                {"ip": p.ip, "type": p.profile_type, "confidence": p.confidence,
                 "in_degree": p.in_degree, "out_degree": p.out_degree,
                 "betweenness": p.betweenness, "pagerank": p.pagerank,
                 "clustering": p.clustering_coefficient, "evidence": p.evidence}
                for p in profiles[:50]
            ],
            "c2_infrastructure": c2_map,
            "graph_summary": {
                "node_count": graph.node_count,
                "edge_count": graph.edge_count,
                "cluster_count": len(clusters),
                "anomaly_count": len(anomalies),
                "c2_candidates": c2_map["summary"]["total_candidates"],
                "suspicious_clusters": sum(1 for c in clusters if c.threat_score > 40),
            },
        }
