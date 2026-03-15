/**
 * AdvancedVisualizationsPanel — Unified panel that combines all 8
 * advanced visualizations into a tabbed interface for the NetForensics
 * investigation dashboard.
 *
 * Consumes data from the existing App state (analysis, stats, graph, etc.)
 * and dispatches them to the individual visualization components.
 */
import { useState, useMemo } from "react";
import {
  CommunicationGraph,
  TorCircuitVisualization,
  MalwareBeaconTimeline,
  EndpointSuspicionHeatmap,
  EncryptedTrafficClassification,
  AnomalyTimeline,
  AttackCampaignClustering,
  GeographicCommunicationMap,
} from "./visualizations";

// Design tokens (mirrors App.jsx)
const C = {
  bg0: "#04070d", bg1: "#080e18", bg2: "#0c1424", bg3: "#111c30",
  border: "#172236", borderBright: "#1f3050",
  cyan: "#00e5ff", blue: "#2979ff", purple: "#7c4dff",
  green: "#00e676", amber: "#ffab40", red: "#ff1744",
  pink: "#f50057", teal: "#14b8a6",
  text: "#d0dae8", textSub: "#5a7499", textDim: "#2e4a6a",
};

const VIEWS = [
  { id: "commGraph",    label: "Communication Graph",   icon: "⬡",  color: C.cyan },
  { id: "torCircuits",  label: "Tor Circuits",          icon: "🧅", color: "#8b5cf6" },
  { id: "beaconTime",   label: "Beacon Timeline",       icon: "⚡",  color: C.red },
  { id: "heatmap",      label: "Endpoint Heatmap",      icon: "▦",  color: C.amber },
  { id: "encryption",   label: "Traffic Classification",icon: "🔐", color: C.purple },
  { id: "anomaly",      label: "Anomaly Timeline",      icon: "◈",  color: C.red },
  { id: "campaigns",    label: "Campaign Clusters",     icon: "⬟",  color: C.cyan },
  { id: "geoMap",       label: "Geographic Map",        icon: "🌐", color: C.green },
];

export default function AdvancedVisualizationsPanel({
  // Data from parent App state
  analysis,
  stats,
  graph,
  graphNodes,
  torData,
  livePackets = [],
  activeSid,
}) {
  const [activeView, setActiveView] = useState("commGraph");

  // Derived data
  const suspiciousIps = useMemo(() =>
    new Set((analysis?.suspicious_ips || [])
      .filter(x => x.suspicion_score > 40)
      .map(x => x.ip)),
    [analysis]
  );

  const enrichedEndpoints = useMemo(() =>
    (analysis?.suspicious_ips || []).map(ep => ({
      ...ep,
      dga_count: ep.dga_domains?.length || 0,
    })),
    [analysis]
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {/* View selector bar */}
      <div style={{
        display: "flex", gap: 4, marginBottom: 16,
        padding: "8px 10px",
        background: `linear-gradient(90deg, ${C.bg3}, ${C.bg2})`,
        borderRadius: 10, border: `1px solid ${C.border}`,
        overflowX: "auto",
      }}>
        {VIEWS.map(v => {
          const active = activeView === v.id;
          return (
            <button
              key={v.id}
              onClick={() => setActiveView(v.id)}
              style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "7px 14px",
                borderRadius: 7,
                border: `1px solid ${active ? v.color + "50" : "transparent"}`,
                background: active ? `${v.color}15` : "transparent",
                color: active ? v.color : C.textSub,
                fontSize: 11, fontWeight: active ? 700 : 500,
                cursor: "pointer",
                whiteSpace: "nowrap",
                transition: "all 0.15s",
              }}
            >
              <span style={{ fontSize: 14 }}>{v.icon}</span>
              {v.label}
            </button>
          );
        })}
      </div>

      {/* Active visualization */}
      <div style={{
        background: C.bg2,
        border: `1px solid ${C.border}`,
        borderRadius: 10,
        overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "12px 18px",
          borderBottom: `1px solid ${C.border}`,
          background: `linear-gradient(90deg, ${C.bg3}, ${C.bg2})`,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 16 }}>
              {VIEWS.find(v => v.id === activeView)?.icon}
            </span>
            <span style={{
              color: C.text, fontWeight: 700, fontSize: 13, letterSpacing: 0.3,
            }}>
              {VIEWS.find(v => v.id === activeView)?.label}
            </span>
          </div>
          {!activeSid && (
            <span style={{
              fontSize: 10, color: C.textDim,
              fontFamily: "'IBM Plex Mono', monospace",
            }}>
              Select a session to load data
            </span>
          )}
        </div>

        {/* Content */}
        <div style={{ padding: 18 }}>
          {activeView === "commGraph" && (
            <CommunicationGraph
              nodes={graphNodes || []}
              edges={graph?.edges || []}
              suspiciousIps={suspiciousIps}
              height={520}
            />
          )}

          {activeView === "torCircuits" && (
            <TorCircuitVisualization
              circuits={torData?.circuits || []}
              sessionId={activeSid}
            />
          )}

          {activeView === "beaconTime" && (
            <MalwareBeaconTimeline
              beacons={analysis?.beacons || []}
              livePackets={livePackets}
            />
          )}

          {activeView === "heatmap" && (
            <EndpointSuspicionHeatmap
              endpoints={enrichedEndpoints}
            />
          )}

          {activeView === "encryption" && (
            <EncryptedTrafficClassification
              tlsFingerprints={stats?.tls_fingerprints || []}
              flows={stats?.flows || []}
            />
          )}

          {activeView === "anomaly" && (
            <AnomalyTimeline
              beacons={analysis?.beacons || []}
              exfilAlerts={analysis?.exfil_alerts || []}
              dgaAlerts={analysis?.dga_alerts || []}
              ttlProfiles={analysis?.ttl_profiles || []}
              torEvents={torData?.top_events || []}
              timeline={stats?.timeline || []}
            />
          )}

          {activeView === "campaigns" && (
            <AttackCampaignClustering
              beacons={analysis?.beacons || []}
              exfilAlerts={analysis?.exfil_alerts || []}
              dgaAlerts={analysis?.dga_alerts || []}
              suspiciousIps={analysis?.suspicious_ips || []}
              clusters={analysis?.clusters || []}
            />
          )}

          {activeView === "geoMap" && (
            <GeographicCommunicationMap
              edges={graph?.edges || []}
              suspiciousIps={suspiciousIps}
              nodes={graphNodes || []}
            />
          )}
        </div>
      </div>
    </div>
  );
}
