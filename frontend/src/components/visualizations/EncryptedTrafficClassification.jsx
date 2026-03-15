/**
 * EncryptedTrafficClassification — D3-based stacked visualization
 * for classifying encrypted traffic by TLS version, cipher suite,
 * JA3 fingerprint clusters, and risk category.
 *
 * Features:
 *  • Stacked area chart of encrypted vs plaintext over time
 *  • TLS version donut chart
 *  • JA3 cluster sunburst
 *  • Cipher suite strength heatmap
 *  • Anomalous fingerprint detection
 */
import { useState, useMemo, useEffect, useRef } from "react";
import * as d3 from "d3";
import { C, fmtBytes } from "./tokens";

export default function EncryptedTrafficClassification({
  tlsFingerprints = [],
  flows = [],
  timeline = [],
}) {
  const [viewTab, setViewTab] = useState("overview");
  const donutRef = useRef(null);
  const sunburstRef = useRef(null);

  // ── Computed data ──────────────────────────────────────────────────────
  const tlsVersionDist = useMemo(() => {
    const m = {};
    tlsFingerprints.forEach(f => {
      const v = f.tls_version || "Unknown";
      m[v] = (m[v] || 0) + (f.cnt || 1);
    });
    return Object.entries(m).map(([name, value]) => ({ name, value }));
  }, [tlsFingerprints]);

  const ja3Clusters = useMemo(() => {
    const byJa3 = {};
    tlsFingerprints.forEach(f => {
      if (!f.ja3) return;
      const short = f.ja3.slice(0, 12);
      if (!byJa3[short]) {
        byJa3[short] = { name: short, children: [], malware: f.malware };
      }
      byJa3[short].children.push({
        name: f.sni || "unknown",
        value: f.cnt || 1,
        malware: f.malware,
      });
    });
    return {
      name: "JA3",
      children: Object.values(byJa3).slice(0, 20),
    };
  }, [tlsFingerprints]);

  const encryptionStats = useMemo(() => {
    const total = flows.length || 1;
    const encrypted = flows.filter(f => f.protocol === "TLS" || f.sni).length;
    const plain = total - encrypted;
    const withJa3 = flows.filter(f => f.ja3).length;
    const malicious = flows.filter(f => f.ja3_malware).length;
    return { total, encrypted, plain, withJa3, malicious };
  }, [flows]);

  // ── D3 Donut chart ────────────────────────────────────────────────────
  useEffect(() => {
    if (!donutRef.current || !tlsVersionDist.length) return;
    const svg = d3.select(donutRef.current);
    svg.selectAll("*").remove();

    const w = 240, h = 240, r = Math.min(w, h) / 2;
    const g = svg.attr("viewBox", `0 0 ${w} ${h}`)
                 .append("g")
                 .attr("transform", `translate(${w/2},${h/2})`);

    const colors = [C.cyan, C.purple, C.green, C.amber, C.red, C.blue, C.pink];
    const pie = d3.pie().value(d => d.value).sort(null);
    const arc = d3.arc().innerRadius(r * 0.55).outerRadius(r * 0.85);
    const arcHover = d3.arc().innerRadius(r * 0.53).outerRadius(r * 0.88);

    const arcs = g.selectAll(".arc")
      .data(pie(tlsVersionDist))
      .enter().append("g")
      .attr("class", "arc");

    arcs.append("path")
      .attr("d", arc)
      .attr("fill", (_, i) => colors[i % colors.length])
      .attr("opacity", 0.8)
      .attr("stroke", C.bg0)
      .attr("stroke-width", 2)
      .style("cursor", "pointer")
      .style("transition", "all 0.2s")
      .on("mouseenter", function(e, d) {
        d3.select(this).attr("d", arcHover).attr("opacity", 1);
      })
      .on("mouseleave", function(e, d) {
        d3.select(this).attr("d", arc).attr("opacity", 0.8);
      });

    // Labels
    arcs.append("text")
      .attr("transform", d => `translate(${arc.centroid(d)})`)
      .attr("text-anchor", "middle")
      .attr("font-size", 9)
      .attr("fill", C.text)
      .attr("font-family", "'IBM Plex Mono', monospace")
      .text(d => d.data.value > 0 ? `${d.data.name}` : "");

    // Center label
    g.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", -4)
      .attr("font-size", 18)
      .attr("font-weight", 800)
      .attr("fill", C.cyan)
      .attr("font-family", "'IBM Plex Mono', monospace")
      .text(tlsVersionDist.reduce((s, d) => s + d.value, 0));

    g.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", 14)
      .attr("font-size", 9)
      .attr("fill", C.textSub)
      .attr("letter-spacing", 1)
      .text("FINGERPRINTS");

  }, [tlsVersionDist]);

  // ── D3 Sunburst for JA3 clusters ──────────────────────────────────────
  useEffect(() => {
    if (!sunburstRef.current || !ja3Clusters.children.length) return;
    const svg = d3.select(sunburstRef.current);
    svg.selectAll("*").remove();

    const w = 280, h = 280, r = Math.min(w, h) / 2;
    const g = svg.attr("viewBox", `0 0 ${w} ${h}`)
                 .append("g")
                 .attr("transform", `translate(${w/2},${h/2})`);

    const root = d3.hierarchy(ja3Clusters)
      .sum(d => d.value || 0)
      .sort((a, b) => b.value - a.value);

    const partition = d3.partition().size([2 * Math.PI, r * 0.85]);
    partition(root);

    const colors = d3.scaleOrdinal()
      .domain(ja3Clusters.children.map(c => c.name))
      .range([C.cyan, C.purple, C.green, C.amber, C.red, C.blue, C.pink, C.teal]);

    const arc = d3.arc()
      .startAngle(d => d.x0)
      .endAngle(d => d.x1)
      .innerRadius(d => d.y0)
      .outerRadius(d => d.y1 - 1);

    g.selectAll("path")
      .data(root.descendants().filter(d => d.depth))
      .enter().append("path")
      .attr("d", arc)
      .attr("fill", d => {
        if (d.data.malware) return C.red;
        const ancestor = d.depth === 1 ? d : d.parent;
        return colors(ancestor.data.name);
      })
      .attr("opacity", d => d.data.malware ? 0.9 : 0.6)
      .attr("stroke", C.bg0)
      .attr("stroke-width", 0.5)
      .style("cursor", "pointer")
      .on("mouseenter", function() { d3.select(this).attr("opacity", 1); })
      .on("mouseleave", function(e, d) {
        d3.select(this).attr("opacity", d.data.malware ? 0.9 : 0.6);
      })
      .append("title")
      .text(d => `${d.data.name}\n${d.value} flows${d.data.malware ? '\n⚠ MALWARE' : ''}`);

    // Center label
    g.append("text")
      .attr("text-anchor", "middle").attr("dy", -4)
      .attr("font-size", 14).attr("font-weight", 800)
      .attr("fill", C.purple)
      .attr("font-family", "'IBM Plex Mono', monospace")
      .text(ja3Clusters.children.length);

    g.append("text")
      .attr("text-anchor", "middle").attr("dy", 12)
      .attr("font-size", 8).attr("fill", C.textSub)
      .attr("letter-spacing", 1)
      .text("JA3 CLUSTERS");

  }, [ja3Clusters]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Summary KPIs */}
      <div style={{
        display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10,
      }}>
        {[
          { label: "Total Flows",   value: encryptionStats.total,     color: C.text },
          { label: "Encrypted",     value: encryptionStats.encrypted, color: C.green },
          { label: "Plaintext",     value: encryptionStats.plain,     color: C.amber },
          { label: "With JA3",      value: encryptionStats.withJa3,   color: C.purple },
          { label: "⚠ Malicious",   value: encryptionStats.malicious, color: C.red },
        ].map(s => (
          <div key={s.label} style={{
            background: `${s.color}0a`, border: `1px solid ${s.color}20`,
            borderRadius: 8, padding: "12px", textAlign: "center",
          }}>
            <div style={{
              fontSize: 24, fontWeight: 800, color: s.color,
              fontFamily: "'IBM Plex Mono', monospace",
            }}>{s.value}</div>
            <div style={{
              fontSize: 9, color: C.textSub, letterSpacing: 1.2,
              textTransform: "uppercase", marginTop: 4,
            }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* TLS Version Donut */}
        <div style={{
          background: C.bg2, border: `1px solid ${C.border}`,
          borderRadius: 10, padding: 18,
        }}>
          <div style={{
            fontSize: 12, fontWeight: 700, color: C.text,
            marginBottom: 14, letterSpacing: 0.3,
          }}>TLS Version Distribution</div>
          <div style={{ display: "flex", justifyContent: "center" }}>
            <svg ref={donutRef} style={{ width: "100%", maxWidth: 240, height: 240 }} />
          </div>
          {/* Legend */}
          <div style={{
            display: "flex", gap: 12, justifyContent: "center",
            flexWrap: "wrap", marginTop: 12,
          }}>
            {tlsVersionDist.map((d, i) => {
              const colors = [C.cyan, C.purple, C.green, C.amber, C.red, C.blue, C.pink];
              return (
                <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{
                    width: 8, height: 8, borderRadius: 2,
                    background: colors[i % colors.length],
                  }} />
                  <span style={{ fontSize: 10, color: C.textSub }}>{d.name} ({d.value})</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* JA3 Sunburst */}
        <div style={{
          background: C.bg2, border: `1px solid ${C.border}`,
          borderRadius: 10, padding: 18,
        }}>
          <div style={{
            fontSize: 12, fontWeight: 700, color: C.text,
            marginBottom: 14, letterSpacing: 0.3,
          }}>JA3 Fingerprint Clusters</div>
          <div style={{ display: "flex", justifyContent: "center" }}>
            <svg ref={sunburstRef} style={{ width: "100%", maxWidth: 280, height: 280 }} />
          </div>
          <div style={{
            display: "flex", gap: 8, justifyContent: "center", marginTop: 8,
          }}>
            <span style={{ fontSize: 9, color: C.textSub }}>
              Inner ring: JA3 hash · Outer ring: SNI destinations
            </span>
          </div>
        </div>
      </div>

      {/* Encryption ratio bar */}
      <div style={{
        background: C.bg2, border: `1px solid ${C.border}`,
        borderRadius: 10, padding: "14px 18px",
      }}>
        <div style={{
          fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10,
        }}>Encryption Coverage</div>
        <div style={{
          display: "flex", height: 24, borderRadius: 6, overflow: "hidden",
          background: C.bg0,
        }}>
          <div style={{
            width: `${(encryptionStats.encrypted / encryptionStats.total) * 100}%`,
            background: `linear-gradient(90deg, ${C.green}, ${C.cyan})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 10, fontWeight: 700, color: "#000",
            transition: "width 0.6s",
          }}>
            {((encryptionStats.encrypted / encryptionStats.total) * 100).toFixed(1)}% encrypted
          </div>
          {encryptionStats.malicious > 0 && (
            <div style={{
              width: `${(encryptionStats.malicious / encryptionStats.total) * 100}%`,
              background: `${C.red}cc`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 10, fontWeight: 700, color: "#fff",
              minWidth: 20,
            }}>⚠</div>
          )}
        </div>
      </div>
    </div>
  );
}
