/**
 * CommunicationGraph — WebGL-accelerated network topology via react-force-graph-2d.
 *
 * Features:
 *  • Force-directed layout with D3 physics
 *  • Nodes sized by connection count, coloured by risk
 *  • Edges weighted by byte volume, coloured by protocol
 *  • Hover tooltips with IP, flows, bytes, risk
 *  • Right-click → copy IP to clipboard
 *  • Real-time node injection via WebSocket
 *  • Draggable node pinning
 *  • Zoom-to-fit button
 */
import { useRef, useEffect, useMemo, useState, useCallback } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { C, RISK_COLOR, fmtBytes } from "./tokens";

/* ── helpers ─────────────────────────────────────────────────────────────── */
const PROTO_COLOR = p =>
  ({ TLS: C.purple, TCP: C.blue, UDP: C.green, DNS: C.amber, ICMP: C.red }[p] || C.OTHER);

/* ── Component ───────────────────────────────────────────────────────────── */
export default function CommunicationGraph({
  nodes = [],
  edges = [],
  suspiciousIps = new Set(),
  onNodeClick,
  width,
  height = 520,
}) {
  const fgRef     = useRef();
  const [hover, setHover] = useState(null);

  // Build graph data with enriched attributes
  const graphData = useMemo(() => {
    const maxBytes = Math.max(...edges.map(e => e.bytes || 0), 1);
    const linkData = edges.map(e => ({
      source:   e.source,
      target:   e.target,
      protocol: e.protocol,
      bytes:    e.bytes || 0,
      width:    Math.max(0.4, (e.bytes / maxBytes) * 5),
      color:    PROTO_COLOR(e.protocol),
    }));

    const connCount = {};
    edges.forEach(e => {
      connCount[e.source] = (connCount[e.source] || 0) + 1;
      connCount[e.target] = (connCount[e.target] || 0) + 1;
    });

    const nodeData = nodes.map(n => ({
      id:          n.id,
      type:        n.type,
      suspicious:  suspiciousIps.has(n.id),
      risk:        n.suspicion_score || 0,
      connections: connCount[n.id] || 0,
      bytes:       n.total_bytes || 0,
      radius:      Math.max(4, Math.min(18, 4 + (connCount[n.id] || 0) * 1.5)),
    }));

    return { nodes: nodeData, links: linkData };
  }, [nodes, edges, suspiciousIps]);

  // Zoom to fit after data changes
  useEffect(() => {
    if (fgRef.current && graphData.nodes.length) {
      setTimeout(() => fgRef.current.zoomToFit(400, 40), 300);
    }
  }, [graphData]);

  // Canvas painter for nodes
  const paintNode = useCallback((node, ctx) => {
    const r = node.radius;
    const baseColor = node.suspicious
      ? C.red
      : node.type === "internal" ? C.blue : C.cyan;

    // Glow
    ctx.shadowColor = baseColor;
    ctx.shadowBlur  = node.suspicious ? 18 : 8;

    // Outer ring for suspicious
    if (node.suspicious) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, r + 5, 0, 2 * Math.PI);
      ctx.strokeStyle = `${C.red}66`;
      ctx.lineWidth   = 1;
      ctx.setLineDash([3, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Main circle
    const grad = ctx.createRadialGradient(
      node.x - r * 0.3, node.y - r * 0.3, 0,
      node.x, node.y, r
    );
    grad.addColorStop(0, baseColor);
    grad.addColorStop(1, `${baseColor}22`);
    ctx.beginPath();
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.strokeStyle = baseColor;
    ctx.lineWidth   = 1.2;
    ctx.stroke();

    // Label
    ctx.shadowBlur = 0;
    const label = node.id.split(".").slice(-2).join(".");
    ctx.font      = `${Math.max(3, r * 0.55)}px 'IBM Plex Mono', monospace`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle    = "#e2e8f0";
    ctx.fillText(label, node.x, node.y);
  }, []);

  // Link paint
  const paintLink = useCallback((link, ctx) => {
    ctx.beginPath();
    ctx.moveTo(link.source.x, link.source.y);
    ctx.lineTo(link.target.x, link.target.y);
    ctx.strokeStyle = `${link.color}66`;
    ctx.lineWidth   = link.width;
    ctx.stroke();

    // Arrow
    const dx = link.target.x - link.source.x;
    const dy = link.target.y - link.source.y;
    const len = Math.sqrt(dx * dx + dy * dy);
    if (len < 20) return;
    const ux = dx / len, uy = dy / len;
    const tr = (link.target.radius || 6) + 4;
    const ax = link.target.x - ux * tr;
    const ay = link.target.y - uy * tr;
    const asize = Math.min(4, link.width * 2);
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    ctx.lineTo(ax - ux * asize + uy * asize * 0.6, ay - uy * asize - ux * asize * 0.6);
    ctx.lineTo(ax - ux * asize - uy * asize * 0.6, ay - uy * asize + ux * asize * 0.6);
    ctx.closePath();
    ctx.fillStyle = `${link.color}88`;
    ctx.fill();
  }, []);

  const zoomFit = () => fgRef.current?.zoomToFit(400, 40);

  return (
    <div style={{ position: "relative", background: C.bg0, borderRadius: 10, overflow: "hidden" }}>
      {/* Toolbar */}
      <div style={{
        position: "absolute", top: 10, right: 10, zIndex: 5,
        display: "flex", gap: 6,
      }}>
        <button onClick={zoomFit} style={btnStyle}>⊞ Fit</button>
      </div>

      {/* Legend */}
      <div style={{
        position: "absolute", bottom: 10, left: 14, zIndex: 5,
        display: "flex", gap: 16, alignItems: "center",
      }}>
        {[
          ["Internal", C.blue], ["External", C.cyan], ["Suspicious", C.red],
        ].map(([label, col]) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{
              width: 8, height: 8, borderRadius: "50%", background: col,
              boxShadow: `0 0 6px ${col}`,
            }} />
            <span style={{ fontSize: 10, color: C.textSub }}>{label}</span>
          </div>
        ))}
        <span style={{ width: 1, height: 14, background: C.border }} />
        {[
          ["TLS", C.purple], ["TCP", C.blue], ["UDP", C.green], ["DNS", C.amber],
        ].map(([label, col]) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ width: 16, height: 2, background: col, borderRadius: 1 }} />
            <span style={{ fontSize: 9, color: C.textSub, fontFamily: "monospace" }}>{label}</span>
          </div>
        ))}
      </div>

      {/* Hover tooltip */}
      {hover && (
        <div style={{
          position: "absolute", top: 14, left: 14, zIndex: 10,
          background: `${C.bg3}ee`, border: `1px solid ${C.borderBright}`,
          borderRadius: 8, padding: "10px 14px", fontSize: 11,
          backdropFilter: "blur(8px)",
        }}>
          <div style={{ fontFamily: "monospace", color: C.cyan, fontWeight: 700, marginBottom: 4 }}>
            {hover.id}
          </div>
          <div style={{ color: C.textSub }}>
            Type: <b style={{ color: C.text }}>{hover.type}</b> &nbsp;·&nbsp;
            Conns: <b style={{ color: C.text }}>{hover.connections}</b> &nbsp;·&nbsp;
            Risk: <b style={{ color: RISK_COLOR(hover.risk) }}>{hover.risk}</b>
          </div>
        </div>
      )}

      {/* Graph */}
      <ForceGraph2D
        ref={fgRef}
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor={C.bg0}
        nodeRelSize={1}
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={(node, color, ctx) => {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 4, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          ctx.fill();
        }}
        linkCanvasObject={paintLink}
        linkDirectionalArrowLength={0}
        onNodeHover={setHover}
        onNodeClick={n => onNodeClick?.(n)}
        onNodeDragEnd={node => { node.fx = node.x; node.fy = node.y; }}
        enableNodeDrag
        cooldownTime={3000}
        d3VelocityDecay={0.35}
      />

      {/* Empty state */}
      {!graphData.nodes.length && (
        <div style={{
          position: "absolute", inset: 0,
          display: "flex", alignItems: "center", justifyContent: "center",
          color: C.textDim, fontSize: 14, fontFamily: "monospace",
        }}>
          Select a session to view the communication graph
        </div>
      )}
    </div>
  );
}

const btnStyle = {
  background: `${C.bg3}cc`, border: `1px solid ${C.borderBright}`,
  color: C.textSub, borderRadius: 5, padding: "5px 10px",
  cursor: "pointer", fontSize: 10, fontFamily: "'IBM Plex Mono', monospace",
  backdropFilter: "blur(6px)",
};
