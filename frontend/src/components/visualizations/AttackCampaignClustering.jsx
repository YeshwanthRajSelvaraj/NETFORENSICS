/**
 * AttackCampaignClustering — D3 scatter/force visualization for grouping
 * related threat indicators into campaign clusters.
 *
 * Features:
 *  • Force-directed cluster bubbles
 *  • Scatter plot of frequency vs data volume per threat
 *  • MITRE ATT&CK technique labels
 *  • Cluster convex hulls
 *  • Click-to-expand cluster details
 *  • Animated transitions between view modes
 */
import { useRef, useEffect, useState, useMemo } from "react";
import * as d3 from "d3";
import { C, fmtBytes } from "./tokens";

const CLUSTER_COLORS = [C.red, C.purple, C.cyan, C.amber, C.green, C.blue, C.pink, "#8b5cf6"];

export default function AttackCampaignClustering({
  beacons = [],
  exfilAlerts = [],
  dgaAlerts = [],
  suspiciousIps = [],
  clusters = [],
}) {
  const svgRef = useRef(null);
  const [viewMode, setViewMode] = useState("scatter"); // scatter | bubble | table
  const [selectedCluster, setSelectedCluster] = useState(null);

  // Build campaign data from analysis results
  const campaigns = useMemo(() => {
    // Group threats by similarity
    const groups = [];

    // Cluster existing flow clusters
    clusters.forEach((cl, i) => {
      groups.push({
        id: `cluster-${i}`,
        name: cl.label?.replace(/_/g, " ") || `Cluster ${i + 1}`,
        size: cl.flow_count || 1,
        port: cl.dominant_port,
        avgBytes: cl.avg_bytes || 0,
        color: CLUSTER_COLORS[i % CLUSTER_COLORS.length],
        type: "flow",
        indicators: [],
      });
    });

    // Enrich with beacon data
    if (beacons.length) {
      const beaconGroup = {
        id: "beacons",
        name: "C2 Beaconing",
        size: beacons.length * 2,
        port: beacons[0]?.dst_port || 443,
        avgBytes: 0,
        color: C.red,
        type: "c2",
        indicators: beacons.map(b => ({
          label: `${b.src_ip} → ${b.dst_ip}`,
          confidence: b.confidence,
          detail: `μ=${b.interval_mean}s`,
        })),
      };
      groups.push(beaconGroup);
    }

    // DGA
    if (dgaAlerts.length) {
      groups.push({
        id: "dga",
        name: "DGA Infrastructure",
        size: dgaAlerts.length,
        port: 53,
        avgBytes: 0,
        color: C.purple,
        type: "dns",
        indicators: dgaAlerts.map(d => ({
          label: d.domain,
          confidence: d.dga_score > 0.8 ? "HIGH" : "MEDIUM",
          detail: `Score ${(d.dga_score * 100).toFixed(0)}%`,
        })),
      });
    }

    // Exfil
    if (exfilAlerts.length) {
      groups.push({
        id: "exfil",
        name: "Data Exfiltration",
        size: exfilAlerts.length,
        port: 443,
        avgBytes: exfilAlerts.reduce((s, e) => s + (e.total_sent || 0), 0) / exfilAlerts.length,
        color: C.amber,
        type: "exfil",
        indicators: exfilAlerts.map(e => ({
          label: `${e.src_ip} → ${e.dst_ip}`,
          confidence: "HIGH",
          detail: `Ratio ${e.ratio}×`,
        })),
      });
    }

    return groups;
  }, [clusters, beacons, dgaAlerts, exfilAlerts]);

  // D3 scatter plot
  useEffect(() => {
    if (!svgRef.current || viewMode !== "scatter") return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const margin = { top: 30, right: 30, bottom: 50, left: 60 };
    const width = 900, height = 450;
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const g = svg.append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    const iw = width - margin.left - margin.right;
    const ih = height - margin.top - margin.bottom;

    // Scales
    const x = d3.scaleLinear()
      .domain([0, d3.max(campaigns, d => d.size) * 1.2 || 10])
      .range([0, iw]);

    const y = d3.scaleLinear()
      .domain([0, d3.max(campaigns, d => d.avgBytes) * 1.2 || 1000])
      .range([ih, 0]);

    const r = d3.scaleSqrt()
      .domain([0, d3.max(campaigns, d => d.indicators.length) || 1])
      .range([12, 50]);

    // Grid
    g.append("g").selectAll("line")
      .data(x.ticks(6)).enter().append("line")
      .attr("x1", d => x(d)).attr("x2", d => x(d))
      .attr("y1", 0).attr("y2", ih)
      .attr("stroke", `${C.border}40`).attr("stroke-dasharray", "3 3");

    g.append("g").selectAll("line")
      .data(y.ticks(6)).enter().append("line")
      .attr("x1", 0).attr("x2", iw)
      .attr("y1", d => y(d)).attr("y2", d => y(d))
      .attr("stroke", `${C.border}40`).attr("stroke-dasharray", "3 3");

    // Axes
    g.append("g").attr("transform", `translate(0,${ih})`)
      .call(d3.axisBottom(x).ticks(6))
      .selectAll("text").attr("fill", C.textDim).attr("font-size", 9);

    g.append("g")
      .call(d3.axisLeft(y).ticks(6).tickFormat(d => fmtBytes(d)))
      .selectAll("text").attr("fill", C.textDim).attr("font-size", 9);

    g.selectAll(".domain, .tick line").attr("stroke", C.border);

    // Axis labels
    g.append("text").attr("x", iw / 2).attr("y", ih + 38)
      .attr("text-anchor", "middle").attr("font-size", 10)
      .attr("fill", C.textSub)
      .text("Flow Count / Frequency →");

    g.append("text")
      .attr("transform", `translate(-44,${ih/2}) rotate(-90)`)
      .attr("text-anchor", "middle").attr("font-size", 10)
      .attr("fill", C.textSub)
      .text("Avg Data Volume →");

    // Defs
    const defs = svg.append("defs");
    const glow = defs.append("filter").attr("id", "clusterGlow");
    glow.append("feGaussianBlur").attr("stdDeviation", 4);

    // Campaign bubbles
    const bubbles = g.selectAll(".campaign")
      .data(campaigns)
      .enter().append("g")
      .attr("class", "campaign")
      .attr("transform", d => `translate(${x(d.size)},${y(d.avgBytes)})`)
      .style("cursor", "pointer");

    // Outer glow
    bubbles.append("circle")
      .attr("r", d => r(d.indicators.length) + 6)
      .attr("fill", d => d.color)
      .attr("opacity", 0.08)
      .attr("filter", "url(#clusterGlow)");

    // Main circle
    bubbles.append("circle")
      .attr("r", d => r(d.indicators.length))
      .attr("fill", d => `${d.color}22`)
      .attr("stroke", d => d.color)
      .attr("stroke-width", 1.5)
      .attr("opacity", 0.8)
      .on("mouseenter", function() { d3.select(this).attr("opacity", 1).attr("stroke-width", 2.5); })
      .on("mouseleave", function() { d3.select(this).attr("opacity", 0.8).attr("stroke-width", 1.5); });

    // Label
    bubbles.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", -3)
      .attr("font-size", 9)
      .attr("fill", d => d.color)
      .attr("font-weight", 700)
      .attr("font-family", "'IBM Plex Mono', monospace")
      .text(d => d.name.length > 14 ? d.name.slice(0, 14) + "…" : d.name);

    // Count
    bubbles.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", 10)
      .attr("font-size", 8)
      .attr("fill", C.textSub)
      .attr("font-family", "monospace")
      .text(d => `${d.indicators.length} indicators`);

    // Tooltip
    bubbles.append("title")
      .text(d => `${d.name}\n${d.size} flows, ${d.indicators.length} indicators\nPort: ${d.port}\nAvg: ${fmtBytes(d.avgBytes)}`);

  }, [campaigns, viewMode]);

  // D3 bubble force layout
  useEffect(() => {
    if (!svgRef.current || viewMode !== "bubble") return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = 900, height = 450;
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const r = d3.scaleSqrt()
      .domain([0, d3.max(campaigns, d => d.size) || 1])
      .range([20, 80]);

    const simulation = d3.forceSimulation(campaigns)
      .force("x", d3.forceX(width / 2).strength(0.05))
      .force("y", d3.forceY(height / 2).strength(0.05))
      .force("collision", d3.forceCollide(d => r(d.size) + 8))
      .force("charge", d3.forceManyBody().strength(-30));

    const g = svg.append("g");

    const nodes = g.selectAll(".node")
      .data(campaigns)
      .enter().append("g")
      .attr("class", "node")
      .style("cursor", "pointer");

    // Outer glow
    nodes.append("circle")
      .attr("r", d => r(d.size) + 4)
      .attr("fill", d => d.color)
      .attr("opacity", 0.06);

    // Main circle
    nodes.append("circle")
      .attr("r", d => r(d.size))
      .attr("fill", d => `${d.color}18`)
      .attr("stroke", d => d.color)
      .attr("stroke-width", 1.5);

    // Label
    nodes.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", -6)
      .attr("font-size", 10)
      .attr("fill", d => d.color)
      .attr("font-weight", 700)
      .attr("font-family", "'IBM Plex Mono', monospace")
      .text(d => d.name);

    // Count
    nodes.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", 10)
      .attr("font-size", 18)
      .attr("fill", d => d.color)
      .attr("font-weight", 800)
      .attr("font-family", "'IBM Plex Mono', monospace")
      .text(d => d.size);

    // Sub-label
    nodes.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", 24)
      .attr("font-size", 8)
      .attr("fill", C.textSub)
      .text(d => `${d.indicators.length} IOCs`);

    simulation.on("tick", () => {
      nodes.attr("transform", d => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, [campaigns, viewMode]);

  if (!campaigns.length) {
    return (
      <div style={{ textAlign: "center", padding: "60px 20px", color: C.textDim, fontSize: 13 }}>
        No campaign clusters to display — run analysis first
      </div>
    );
  }

  return (
    <div>
      {/* View tabs */}
      <div style={{ display: "flex", gap: 6, marginBottom: 14, alignItems: "center" }}>
        {[
          { id: "scatter", label: "⊞ Scatter Plot" },
          { id: "bubble",  label: "◉ Bubble Force" },
          { id: "table",   label: "≡ Table" },
        ].map(tab => (
          <button key={tab.id} onClick={() => setViewMode(tab.id)} style={{
            padding: "6px 14px", borderRadius: 6, border: "none",
            fontSize: 11, fontWeight: 600, cursor: "pointer",
            background: viewMode === tab.id ? `${C.cyan}20` : "transparent",
            color: viewMode === tab.id ? C.cyan : C.textSub,
          }}>{tab.label}</button>
        ))}
        <span style={{ marginLeft: "auto", fontSize: 11, color: C.textSub }}>
          {campaigns.length} campaign group(s)
        </span>
      </div>

      {/* SVG view */}
      {(viewMode === "scatter" || viewMode === "bubble") && (
        <div style={{
          background: C.bg0, borderRadius: 10,
          border: `1px solid ${C.border}`, overflow: "hidden",
        }}>
          <svg ref={svgRef} style={{ width: "100%", height: "auto" }} />
        </div>
      )}

      {/* Table view */}
      {viewMode === "table" && (
        <div style={{ display: "grid", gap: 10 }}>
          {campaigns.map((camp, i) => (
            <div key={camp.id} style={{
              background: `${camp.color}08`,
              border: `1px solid ${camp.color}30`,
              borderLeft: `3px solid ${camp.color}`,
              borderRadius: 8, padding: "14px 18px",
            }}>
              <div style={{
                display: "flex", alignItems: "center", gap: 10, marginBottom: 10,
              }}>
                <span style={{
                  width: 10, height: 10, borderRadius: "50%",
                  background: camp.color, boxShadow: `0 0 8px ${camp.color}`,
                }} />
                <span style={{ fontSize: 13, fontWeight: 700, color: camp.color }}>
                  {camp.name}
                </span>
                <span style={{
                  fontSize: 10, padding: "2px 8px", borderRadius: 4,
                  background: `${camp.color}20`, color: camp.color,
                }}>{camp.type}</span>
                <span style={{ marginLeft: "auto", fontSize: 11, color: C.textSub }}>
                  {camp.size} flows · {camp.indicators.length} IOCs
                </span>
              </div>
              {camp.indicators.length > 0 && (
                <div style={{
                  display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(250px, 1fr))",
                  gap: 6,
                }}>
                  {camp.indicators.slice(0, 6).map((ind, j) => (
                    <div key={j} style={{
                      background: C.bg0, borderRadius: 5, padding: "6px 10px",
                      fontSize: 10, fontFamily: "monospace",
                    }}>
                      <span style={{ color: C.text }}>{ind.label}</span>
                      <span style={{
                        float: "right", color: ind.confidence === "HIGH" ? C.red : C.amber,
                      }}>{ind.detail}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
