// ==============================================================================
// Tracegrid: src/svg_map.rs
// Zero-Dependency Dark-Mode SVG Network Topology & Hop-Latency Chart Generator
// ==============================================================================

use crate::divergence::{DivergenceReport, TraceRun};

/// Escapes special XML characters to prevent XSS and formatting breakage.
pub fn escape_xml(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(c),
        }
    }
    output
}

/// Standalone SVG Topology and Latency Chart Generator.
pub struct SvgMapGenerator;

impl SvgMapGenerator {
    /// Renders a single traceroute run into an SVG document.
    pub fn render_trace(run: &TraceRun) -> String {
        let width = 1200;
        let hop_count = run.hops.len().max(1);
        let height = 620;

        let mut svg = String::with_capacity(8192);

        // Header & defs
        svg.push_str(&format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" width="{}" height="{}">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0b0f19"/>
      <stop offset="50%" stop-color="#111827"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>
    <linearGradient id="cyan-beam" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#00f2fe"/>
      <stop offset="50%" stop-color="#4facfe"/>
      <stop offset="100%" stop-color="#6366f1"/>
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feComposite in="SourceGraphic" in2="blur" operator="over"/>
    </filter>
    <pattern id="grid-pattern" width="40" height="40" patternUnits="userSpaceOnUse">
      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" stroke-width="0.8" stroke-opacity="0.5"/>
    </pattern>
  </defs>

  <!-- Background Base -->
  <rect width="100%" height="100%" fill="url(#bg)"/>
  <rect width="100%" height="100%" fill="url(#grid-pattern)"/>

  <!-- Top Accent Beam -->
  <rect x="0" y="0" width="{}" height="4" fill="url(#cyan-beam)"/>
  <rect x="20" y="20" width="{}" height="{}" rx="10" fill="none" stroke="#1e293b" stroke-width="1.5"/>

  <!-- Header HUD -->
  <g transform="translate(50, 60)">
    <rect x="0" y="-12" width="130" height="26" rx="13" fill="#1e293b" stroke="#334155" stroke-width="1"/>
    <circle cx="14" cy="1" r="5" fill="#10b981" filter="url(#glow)"/>
    <text x="28" y="5" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">TRACE RUN</text>

    <text x="145" y="6" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="22" font-weight="800">TARGET: {}</text>
    <text x="145" y="26" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="12">PROTOCOL: {} | FLOW ID: 0x{:04X} | TIMESTAMP: {}</text>
  </g>
"##,
            width, height, width, height,
            width,
            width - 40, height - 40,
            escape_xml(&run.target),
            escape_xml(&run.protocol.to_string()),
            run.flow_id,
            escape_xml(&run.timestamp)
        ));

        // Topology graph area
        let margin_left = 70.0;
        let margin_right = 70.0;
        let usable_width = (width as f64) - margin_left - margin_right;
        let step_x = if hop_count > 1 {
            usable_width / ((hop_count - 1) as f64)
        } else {
            usable_width / 2.0
        };

        let node_y = 190.0;

        // Draw connecting link lines
        for i in 0..(hop_count.saturating_sub(1)) {
            let x1 = margin_left + (i as f64) * step_x;
            let x2 = margin_left + ((i + 1) as f64) * step_x;
            svg.push_str(&format!(
                r##"  <line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="#334155" stroke-width="3" stroke-dasharray="6,4"/>
  <line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="#00f2fe" stroke-width="1.5"/>
"##,
                x1, node_y, x2, node_y,
                x1, node_y, x2, node_y
            ));
        }

        // Draw Hop Nodes
        for (i, hop) in run.hops.iter().enumerate() {
            let cx = margin_left + (i as f64) * step_x;
            let ip_str = hop
                .ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "* * *".to_string());
            let rtt_str = hop
                .mean_rtt()
                .map(|r| format!("{:.1}ms", r))
                .unwrap_or_else(|| "timeout".to_string());
            let asn_label = hop.asn_label();

            let node_color = if hop.responding { "#00f2fe" } else { "#f43f5e" };
            let fill_color = if hop.responding { "#0f172a" } else { "#311019" };

            svg.push_str(&format!(
                r##"  <!-- Hop {} -->
  <g transform="translate({:.1}, {:.1})">
    <circle cx="0" cy="0" r="18" fill="{}" stroke="{}" stroke-width="2" filter="url(#glow)"/>
    <text x="0" y="5" text-anchor="middle" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="12" font-weight="700">{}</text>

    <!-- IP Badge -->
    <rect x="-55" y="28" width="110" height="20" rx="4" fill="#1e293b" stroke="#334155" stroke-width="1"/>
    <text x="0" y="42" text-anchor="middle" fill="#e2e8f0" font-family="'JetBrains Mono', monospace" font-size="10" font-weight="600">{}</text>

    <!-- ASN Label -->
    <rect x="-65" y="52" width="130" height="18" rx="4" fill="#0f172a" stroke="#1e293b" stroke-width="1"/>
    <text x="0" y="65" text-anchor="middle" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="9">{}</text>

    <!-- RTT Label -->
    <text x="0" y="-26" text-anchor="middle" fill="{}" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">{}</text>
  </g>
"##,
                hop.ttl,
                cx, node_y,
                fill_color, node_color,
                hop.ttl,
                escape_xml(&ip_str),
                escape_xml(&asn_label),
                node_color,
                escape_xml(&rtt_str)
            ));
        }

        // Latency Chart Section
        let chart_top = 340.0;
        let chart_height = 200.0;
        let chart_width = usable_width;
        let chart_x = margin_left;

        svg.push_str(&format!(
            r##"  <!-- Latency Metric Graph -->
  <g transform="translate({:.1}, {:.1})">
    <rect width="{:.1}" height="{:.1}" rx="8" fill="#090d16" stroke="#1e293b" stroke-width="1.2"/>
    <text x="20" y="26" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="12" font-weight="700">HOP-BY-HOP ROUND-TRIP LATENCY (ms)</text>

    <!-- Chart Gridlines -->
    <line x1="20" y1="50" x2="{:.1}" y2="50" stroke="#1e293b" stroke-width="1" stroke-dasharray="4,4"/>
    <text x="25" y="46" fill="#475569" font-family="'JetBrains Mono', monospace" font-size="9">100ms</text>
    <line x1="20" y1="100" x2="{:.1}" y2="100" stroke="#1e293b" stroke-width="1" stroke-dasharray="4,4"/>
    <text x="25" y="96" fill="#475569" font-family="'JetBrains Mono', monospace" font-size="9">50ms</text>
    <line x1="20" y1="150" x2="{:.1}" y2="150" stroke="#1e293b" stroke-width="1" stroke-dasharray="4,4"/>
    <text x="25" y="146" fill="#475569" font-family="'JetBrains Mono', monospace" font-size="9">20ms</text>
"##,
            chart_x, chart_top,
            chart_width, chart_height,
            chart_width - 20.0,
            chart_width - 20.0,
            chart_width - 20.0
        ));

        // Draw latency bars
        let max_rtt = run
            .hops
            .iter()
            .filter_map(|h| h.mean_rtt())
            .fold(10.0f64, f64::max)
            .max(50.0);

        for (i, hop) in run.hops.iter().enumerate() {
            let bar_cx = 20.0 + (i as f64) * ((chart_width - 40.0) / hop_count as f64) + 10.0;
            let bar_w = ((chart_width - 40.0) / (hop_count as f64) * 0.6).clamp(8.0, 36.0);
            let rtt = hop.mean_rtt().unwrap_or(0.0);
            let bar_h = ((rtt / max_rtt) * 120.0).clamp(2.0, 120.0);
            let bar_y = 175.0 - bar_h;

            let fill = if hop.responding { "#00f2fe" } else { "#f43f5e" };

            svg.push_str(&format!(
                r##"    <rect x="{:.1}" y="{:.1}" width="{:.1}" height="{:.1}" rx="3" fill="{}" opacity="0.85"/>
    <text x="{:.1}" y="190" text-anchor="middle" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="9">H{}</text>
"##,
                bar_cx - (bar_w / 2.0),
                bar_y,
                bar_w,
                bar_h,
                fill,
                bar_cx,
                hop.ttl
            ));
        }

        svg.push_str("  </g>\n");

        // Footer
        svg.push_str(
            r##"  <!-- Footer HUD -->
  <g transform="translate(50, 585)">
    <text x="0" y="0" fill="#475569" font-family="'JetBrains Mono', monospace" font-size="11">TRACEGRID v0.1.0 // PARIS-TRACEROUTE FLOW ENGINE // RFC 1071 16-BIT INVARIANT CHECKSUM // RFC 3550 EWMA JITTER</text>
  </g>
</svg>
"##,
        );

        svg
    }

    /// Renders a side-by-side comparison between baseline and active traces from a DivergenceReport.
    pub fn render_divergence_report(report: &DivergenceReport) -> String {
        let width = 1200;
        let height = 740;

        let mut svg = String::with_capacity(10240);

        let status_color = if report.detected_hijack {
            "#ef4444"
        } else if report.detected_flaps || report.max_latency_spike_ms > 25.0 {
            "#f59e0b"
        } else {
            "#10b981"
        };

        let status_badge = if report.detected_hijack {
            "BGP HIJACK DETECTED"
        } else if report.detected_flaps {
            "ROUTE FLAPPING"
        } else if report.max_latency_spike_ms > 25.0 {
            "LATENCY DIVERGENCE"
        } else {
            "ROUTE STABLE"
        };

        svg.push_str(&format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" width="{}" height="{}">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0a0e17"/>
      <stop offset="50%" stop-color="#101726"/>
      <stop offset="100%" stop-color="#0d1322"/>
    </linearGradient>
    <filter id="glow-crit" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="4" result="blur"/>
      <feComposite in="SourceGraphic" in2="blur" operator="over"/>
    </filter>
    <pattern id="grid-pattern" width="40" height="40" patternUnits="userSpaceOnUse">
      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" stroke-width="0.8" stroke-opacity="0.4"/>
    </pattern>
  </defs>

  <rect width="100%" height="100%" fill="url(#bg)"/>
  <rect width="100%" height="100%" fill="url(#grid-pattern)"/>
  <rect x="0" y="0" width="{}" height="4" fill="{}"/>
  <rect x="20" y="20" width="{}" height="{}" rx="10" fill="none" stroke="#1e293b" stroke-width="1.5"/>

  <!-- Header Section -->
  <g transform="translate(50, 60)">
    <rect x="0" y="-12" width="190" height="26" rx="13" fill="#1e293b" stroke="{}" stroke-width="1.5"/>
    <circle cx="14" cy="1" r="5" fill="{}" filter="url(#glow-crit)"/>
    <text x="28" y="5" fill="{}" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">{}</text>

    <text x="210" y="6" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="22" font-weight="800">TARGET: {}</text>
    <text x="210" y="26" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="12">RISK SCORE: {}/100 | MAX LATENCY DELTA: +{:.2}ms</text>
  </g>
"##,
            width, height, width, height,
            width,
            status_color,
            width - 40, height - 40,
            status_color,
            status_color,
            status_color,
            escape_xml(status_badge),
            escape_xml(&report.target),
            report.risk_score,
            report.max_latency_spike_ms
        ));

        // Diff Table Header
        let table_y = 130.0;
        svg.push_str(&format!(
            r##"  <!-- Diff Table -->
  <g transform="translate(50, {:.1})">
    <rect width="1100" height="40" rx="6" fill="#151e2e" stroke="#25354e" stroke-width="1"/>
    <text x="20" y="25" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">TTL</text>
    <text x="70" y="25" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">SEVERITY</text>
    <text x="160" y="25" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">BASELINE HOP</text>
    <text x="440" y="25" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">ACTIVE HOP</text>
    <text x="730" y="25" fill="#64748b" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">DIAGNOSTIC SUMMARY</text>
"##,
            table_y
        ));

        let mut row_y = 50.0;
        for diff in report.diffs.iter().take(9) {
            let sev_color = match diff.severity {
                crate::divergence::Severity::Info => "#38bdf8",
                crate::divergence::Severity::Warning => "#f59e0b",
                crate::divergence::Severity::Critical => "#ef4444",
            };

            let b_str = match &diff.baseline_hop {
                Some(h) => format!("{:?} ({})", h.ip.map(|x| x.to_string()).unwrap_or_else(|| "*".to_string()), h.asn_label()),
                None => "None".to_string(),
            };

            let a_str = match &diff.active_hop {
                Some(h) => format!("{:?} ({})", h.ip.map(|x| x.to_string()).unwrap_or_else(|| "*".to_string()), h.asn_label()),
                None => "None".to_string(),
            };

            svg.push_str(&format!(
                r##"    <!-- Row -->
    <rect x="0" y="{:.1}" width="1100" height="42" fill="#0c121e" stroke="#1a2538" stroke-width="1"/>
    <text x="20" y="{:.1}" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">H{}</text>
    <text x="70" y="{:.1}" fill="{}" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">{}</text>
    <text x="160" y="{:.1}" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="10">{}</text>
    <text x="440" y="{:.1}" fill="#cbd5e1" font-family="'JetBrains Mono', monospace" font-size="10">{}</text>
    <text x="730" y="{:.1}" fill="{}" font-family="'JetBrains Mono', monospace" font-size="10">{}</text>
"##,
                row_y,
                row_y + 25.0,
                diff.ttl,
                row_y + 25.0,
                sev_color,
                escape_xml(&diff.severity.to_string()),
                row_y + 25.0,
                escape_xml(&b_str),
                row_y + 25.0,
                escape_xml(&a_str),
                row_y + 25.0,
                sev_color,
                escape_xml(&diff.description)
            ));

            row_y += 46.0;
        }

        svg.push_str("  </g>\n");

        // Summary callout box at bottom
        let summary_box_y = table_y + row_y + 20.0;
        svg.push_str(&format!(
            r##"  <!-- Divergence Summary Box -->
  <g transform="translate(50, {:.1})">
    <rect width="1100" height="60" rx="8" fill="#111927" stroke="{}" stroke-width="1.5"/>
    <text x="25" y="26" fill="{}" font-family="'JetBrains Mono', monospace" font-size="12" font-weight="700">ROUTE DIVERGENCE ENGINE AUDIT VERDICT</text>
    <text x="25" y="46" fill="#e2e8f0" font-family="'JetBrains Mono', monospace" font-size="11">{}</text>
  </g>
"##,
            summary_box_y,
            status_color,
            status_color,
            escape_xml(&report.summary)
        ));

        // Footer
        svg.push_str(
            r##"  <!-- Footer -->
  <g transform="translate(50, 715)">
    <text x="0" y="0" fill="#475569" font-family="'JetBrains Mono', monospace" font-size="11">TRACEGRID BGP SECURITY GATE // ASN AUTONOMOUS SYSTEM VERIFICATION // ZERO-DEPENDENCY SVG RENDERER</text>
  </g>
</svg>
"##,
        );

        svg
    }
}
