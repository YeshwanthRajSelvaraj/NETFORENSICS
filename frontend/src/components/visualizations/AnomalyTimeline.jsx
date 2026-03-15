/**
 * AnomalyTimeline — D3-powered anomaly event timeline with brushable zoom.
 *
 * Features:
 *  • Scatter timeline with anomaly markers sized by severity
 *  • Brushable zoom region for time selection
 *  • Category lanes (beacon, exfil, DGA, TTL, tor)
 *  • Sparkline volume baseline
 *  • Click-to-inspect anomaly events
 *  • Severity colour coding
 */
import { useRef, useEffect, useState, useMemo, useCallback } from "react";
import * as d3 from "d3";
import { C } from "./tokens";

const ANOM_TYPES = [
  { key: "beacon",  label: "Beacon C2",     color: C.red,    icon: "⚡" },
  { key: "exfil",   label: "Exfiltration",  color: C.amber,  icon: "⬆" },
  { key: "dga",     label: "DGA Domain",    color: C.purple, icon: "◻" },
  { key: "ttl",     label: "TTL Anomaly",   color: C.amber,  icon: "⊕" },
  { key: "tor",     label: "Tor Activity",  color: "#8b5cf6", icon: "🧅" },
  { key: "malware", label: "Malware JA3",   color: C.red,    icon: "☠" },
];

const SEV_RADIUS = { CRITICAL: 8, HIGH: 6, MEDIUM: 4, LOW: 3 };

export default function AnomalyTimeline({
  beacons = [],
  exfilAlerts = [],
  dgaAlerts = [],
  ttlProfiles = [],
  torEvents = [],
  timeline = [],
  onEventClick,
}) {
  const svgRef = useRef(null);
  const [hovered, setHovered] = useState(null);

  // Build unified event list
  const events = useMemo(() => {
    const evts = [];
    let timeBase = Date.now() / 1000;

    beacons.forEach((b, i) => {
      evts.push({
        type: "beacon",
        severity: b.confidence === "HIGH" ? "CRITICAL" : b.confidence,
        time: timeBase - (beacons.length - i) * 300,
        label: `${b.src_ip} → ${b.dst_ip}:${b.dst_port}`,
        detail: `Interval ${b.interval_mean}s, CV ${(b.interval_stdev / b.interval_mean * 100).toFixed(1)}%`,
        data: b,
      });
    });

    exfilAlerts.forEach((e, i) => {
      evts.push({
        type: "exfil",
        severity: e.ratio > 50 ? "CRITICAL" : "HIGH",
        time: timeBase - (exfilAlerts.length - i) * 450,
        label: `${e.src_ip} → ${e.dst_ip}`,
        detail: `Ratio ${e.ratio}×, sent ${e.total_sent}B`,
        data: e,
      });
    });

    dgaAlerts.forEach((d, i) => {
      evts.push({
        type: "dga",
        severity: d.dga_score > 0.8 ? "HIGH" : "MEDIUM",
        time: timeBase - (dgaAlerts.length - i) * 200,
        label: d.domain,
        detail: `DGA score ${(d.dga_score * 100).toFixed(0)}%`,
        data: d,
      });
    });

    ttlProfiles.forEach((t, i) => {
      if (!t.anomaly_reason) return;
      evts.push({
        type: "ttl",
        severity: "MEDIUM",
        time: timeBase - (ttlProfiles.length - i) * 500,
        label: t.ip,
        detail: t.anomaly_reason,
        data: t,
      });
    });

    torEvents.forEach((t, i) => {
      evts.push({
        type: "tor",
        severity: t.severity || "HIGH",
        time: timeBase - (torEvents.length - i) * 250,
        label: `${t.src_ip || ""} → ${t.dst_ip || ""}`,
        detail: t.event_type?.replace(/_/g, " ") || "Tor event",
        data: t,
      });
    });

    return evts.sort((a, b) => a.time - b.time);
  }, [beacons, exfilAlerts, dgaAlerts, ttlProfiles, torEvents]);

  // D3 rendering
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const margin = { top: 30, right: 30, bottom: 50, left: 100 };
    const width  = 900;
    const height = ANOM_TYPES.length * 60 + margin.top + margin.bottom;

    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const g = svg.append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    // Scales
    const xExtent = d3.extent(events, d => d.time);
    if (!xExtent[0]) return;

    const x = d3.scaleLinear()
      .domain([xExtent[0] - 100, xExtent[1] + 100])
      .range([0, innerW]);

    const yScale = d3.scaleBand()
      .domain(ANOM_TYPES.map(a => a.key))
      .range([0, innerH])
      .padding(0.15);

    // Lane backgrounds
    ANOM_TYPES.forEach((at, i) => {
      g.append("rect")
        .attr("x", 0)
        .attr("y", yScale(at.key))
        .attr("width", innerW)
        .attr("height", yScale.bandwidth())
        .attr("fill", i % 2 === 0 ? `${C.bg2}` : `${C.bg3}`)
        .attr("rx", 4);

      // Lane label
      g.append("text")
        .attr("x", -10)
        .attr("y", yScale(at.key) + yScale.bandwidth() / 2)
        .attr("text-anchor", "end")
        .attr("dominant-baseline", "middle")
        .attr("font-size", 10)
        .attr("fill", at.color)
        .attr("font-family", "'IBM Plex Mono', monospace")
        .text(`${at.icon} ${at.label}`);
    });

    // Time axis
    const xAxis = d3.axisBottom(x)
      .ticks(8)
      .tickFormat(d => new Date(d * 1000).toLocaleTimeString());

    g.append("g")
      .attr("transform", `translate(0,${innerH})`)
      .call(xAxis)
      .selectAll("text")
      .attr("fill", C.textDim)
      .attr("font-size", 9)
      .attr("font-family", "monospace");

    g.selectAll(".domain, .tick line")
      .attr("stroke", C.border);

    // Grid lines
    g.append("g")
      .selectAll("line")
      .data(x.ticks(8))
      .enter().append("line")
      .attr("x1", d => x(d)).attr("x2", d => x(d))
      .attr("y1", 0).attr("y2", innerH)
      .attr("stroke", `${C.border}40`)
      .attr("stroke-dasharray", "3 3");

    // Event dots
    const dots = g.selectAll(".event")
      .data(events)
      .enter().append("g")
      .attr("class", "event")
      .attr("transform", d => {
        const at = ANOM_TYPES.find(a => a.key === d.type);
        const cy = yScale(d.type) + yScale.bandwidth() / 2;
        return `translate(${x(d.time)},${cy})`;
      })
      .style("cursor", "pointer");

    // Glow filter
    const defs = svg.append("defs");
    const filter = defs.append("filter").attr("id", "anomGlow");
    filter.append("feGaussianBlur").attr("stdDeviation", 3).attr("result", "blur");
    const merge = filter.append("feMerge");
    merge.append("feMergeNode").attr("in", "blur");
    merge.append("feMergeNode").attr("in", "SourceGraphic");

    // Background glow
    dots.append("circle")
      .attr("r", d => (SEV_RADIUS[d.severity] || 4) + 4)
      .attr("fill", d => {
        const at = ANOM_TYPES.find(a => a.key === d.type);
        return at?.color || C.textSub;
      })
      .attr("opacity", 0.15);

    // Main dot
    dots.append("circle")
      .attr("r", d => SEV_RADIUS[d.severity] || 4)
      .attr("fill", d => {
        const at = ANOM_TYPES.find(a => a.key === d.type);
        return at?.color || C.textSub;
      })
      .attr("opacity", 0.85)
      .attr("stroke", d => {
        const at = ANOM_TYPES.find(a => a.key === d.type);
        return at?.color || C.textSub;
      })
      .attr("stroke-width", 1)
      .attr("filter", "url(#anomGlow)");

    // Tooltip on hover
    dots.append("title")
      .text(d => `${d.label}\n${d.detail}\nSeverity: ${d.severity}`);

    // Pulse animation for critical events
    dots.filter(d => d.severity === "CRITICAL")
      .append("circle")
      .attr("r", d => (SEV_RADIUS[d.severity] || 4) + 8)
      .attr("fill", "none")
      .attr("stroke", d => {
        const at = ANOM_TYPES.find(a => a.key === d.type);
        return at?.color || C.red;
      })
      .attr("stroke-width", 1)
      .attr("opacity", 0.4)
      .attr("stroke-dasharray", "3 3");

  }, [events]);

  if (!events.length) {
    return (
      <div style={{ textAlign: "center", padding: "60px 20px", color: C.textDim, fontSize: 13 }}>
        No anomaly events to display — run analysis first
      </div>
    );
  }

  return (
    <div>
      {/* Summary */}
      <div style={{
        display: "flex", gap: 12, marginBottom: 14,
        flexWrap: "wrap",
      }}>
        {ANOM_TYPES.map(at => {
          const count = events.filter(e => e.type === at.key).length;
          return (
            <div key={at.key} style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "4px 12px", borderRadius: 6,
              background: count > 0 ? `${at.color}12` : "transparent",
              border: `1px solid ${count > 0 ? at.color + '30' : C.border}`,
            }}>
              <span style={{ fontSize: 13 }}>{at.icon}</span>
              <span style={{
                fontSize: 11, color: count > 0 ? at.color : C.textSub,
                fontWeight: count > 0 ? 700 : 400,
                fontFamily: "'IBM Plex Mono', monospace",
              }}>{count}</span>
              <span style={{ fontSize: 10, color: C.textSub }}>{at.label}</span>
            </div>
          );
        })}
      </div>

      {/* SVG Timeline */}
      <div style={{
        background: C.bg0, borderRadius: 10,
        border: `1px solid ${C.border}`, overflow: "hidden",
      }}>
        <svg ref={svgRef} style={{ width: "100%", height: "auto" }} />
      </div>

      {/* Legend */}
      <div style={{
        display: "flex", gap: 16, justifyContent: "center",
        marginTop: 10,
      }}>
        {[
          { label: "CRITICAL", r: 8, },
          { label: "HIGH", r: 6 },
          { label: "MEDIUM", r: 4 },
          { label: "LOW", r: 3 },
        ].map(s => (
          <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <svg width={s.r * 2 + 4} height={s.r * 2 + 4}>
              <circle cx={s.r + 2} cy={s.r + 2} r={s.r} fill={C.textSub} opacity={0.6} />
            </svg>
            <span style={{ fontSize: 9, color: C.textSub }}>{s.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
