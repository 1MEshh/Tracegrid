#!/usr/bin/env bash
# ==============================================================================
# Tracegrid: scripts/generate_assets.sh
# Generates high-contrast visual assets (banner.svg, preview.png, demo.gif)
# Strips metadata via ImageMagick to enforce zero privacy leaks.
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="${REPO_ROOT}/assets"
mkdir -p "${ASSETS_DIR}"

echo "[ASSETS] Generating banner.svg..."
cat << 'EOF' > "${ASSETS_DIR}/banner.svg"
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 420" width="1200" height="420">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#080c16"/>
      <stop offset="50%" stop-color="#0d1424"/>
      <stop offset="100%" stop-color="#0b101c"/>
    </linearGradient>
    <linearGradient id="cyan-beam" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#00f2fe"/>
      <stop offset="50%" stop-color="#4facfe"/>
      <stop offset="100%" stop-color="#6366f1"/>
    </linearGradient>
    <linearGradient id="flow1" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#00f2fe" stop-opacity="0.9"/>
      <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.3"/>
    </linearGradient>
    <linearGradient id="flow2-hijack" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#f43f5e" stop-opacity="0.9"/>
      <stop offset="100%" stop-color="#fb7185" stop-opacity="0.4"/>
    </linearGradient>
    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#162238" stroke-width="0.9" stroke-opacity="0.5"/>
    </pattern>
    <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="4" result="blur"/>
      <feComposite in="SourceGraphic" in2="blur" operator="over"/>
    </filter>
    <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="4" result="blur"/>
      <feComposite in="SourceGraphic" in2="blur" operator="over"/>
    </filter>
  </defs>

  <!-- Background Base -->
  <rect width="100%" height="100%" fill="url(#bg)"/>
  <rect width="100%" height="100%" fill="url(#grid)"/>

  <!-- Border & Top Accent Beam -->
  <rect x="1" y="1" width="1198" height="418" fill="none" stroke="#1c2b44" stroke-width="1.5"/>
  <rect x="0" y="0" width="1200" height="4" fill="url(#cyan-beam)"/>

  <!-- HUD Corner Accents -->
  <path d="M 25 50 L 25 25 L 50 25" fill="none" stroke="#00f2fe" stroke-width="2.5"/>
  <path d="M 1175 50 L 1175 25 L 1150 25" fill="none" stroke="#00f2fe" stroke-width="2.5"/>
  <path d="M 25 370 L 25 395 L 50 395" fill="none" stroke="#00f2fe" stroke-width="2.5"/>
  <path d="M 1175 370 L 1175 395 L 1150 395" fill="none" stroke="#00f2fe" stroke-width="2.5"/>

  <!-- Top Status Badge -->
  <g transform="translate(60, 42)">
    <rect width="260" height="26" rx="13" fill="#121b2d" stroke="#223352" stroke-width="1"/>
    <circle cx="15" cy="13" r="5" fill="#10b981" filter="url(#glow-cyan)"/>
    <text x="28" y="17" fill="#94a3b8" font-family="'JetBrains Mono', 'Fira Code', monospace" font-size="11" font-weight="700" letter-spacing="1.2">PARIS-TRACEROUTE ENGINE</text>
  </g>

  <!-- Title & Subtitle -->
  <text x="60" y="125" fill="#f8fafc" font-family="'JetBrains Mono', 'Fira Code', monospace" font-size="52" font-weight="900" letter-spacing="2">TRACEGRID</text>
  <text x="390" y="125" fill="#00f2fe" font-family="'JetBrains Mono', monospace" font-size="52" font-weight="900">_</text>

  <text x="60" y="165" fill="#94a3b8" font-family="'JetBrains Mono', sans-serif" font-size="17" font-weight="500" letter-spacing="0.3">
    ECMP-Consistent Multipath Probing, RFC 3550 Jitter &amp; BGP ASN Hijack Detector
  </text>

  <!-- Topological Multi-Path Wave Graphic -->
  <g transform="translate(60, 210)">
    <!-- Baseline Stable Path -->
    <path d="M 0 40 L 180 40 L 320 15 L 500 15 L 680 40 L 860 40 L 1080 40" fill="none" stroke="url(#flow1)" stroke-width="3" filter="url(#glow-cyan)"/>
    <path d="M 0 40 L 180 40 L 320 15 L 500 15 L 680 40 L 860 40 L 1080 40" fill="none" stroke="#ffffff" stroke-width="1" stroke-opacity="0.8"/>

    <!-- Divergent Hijacked Path -->
    <path d="M 180 40 L 320 75 L 500 75 L 680 40" fill="none" stroke="url(#flow2-hijack)" stroke-width="2.5" stroke-dasharray="6,4" filter="url(#glow-red)"/>

    <!-- Nodes -->
    <!-- Hop 1 Gateway -->
    <circle cx="0" cy="40" r="7" fill="#00f2fe" filter="url(#glow-cyan)"/>
    <text x="0" y="62" fill="#64748b" font-family="monospace" font-size="10" text-anchor="middle">H1: LAN</text>

    <!-- Hop 2 Ingress -->
    <circle cx="180" cy="40" r="7" fill="#00f2fe" filter="url(#glow-cyan)"/>
    <text x="180" y="62" fill="#64748b" font-family="monospace" font-size="10" text-anchor="middle">H2: AS64496</text>

    <!-- Hop 3 Baseline Transit -->
    <circle cx="320" cy="15" r="7" fill="#10b981" filter="url(#glow-cyan)"/>
    <text x="320" y="3" fill="#10b981" font-family="monospace" font-size="10" text-anchor="middle">H3: AS174</text>

    <!-- Hop 4 Baseline Destination Ingress -->
    <circle cx="500" cy="15" r="7" fill="#10b981" filter="url(#glow-cyan)"/>
    <text x="500" y="3" fill="#10b981" font-family="monospace" font-size="10" text-anchor="middle">H4: AS13335</text>

    <!-- Hop 3 Divergence Rogue Node -->
    <circle cx="320" cy="75" r="7" fill="#ef4444" filter="url(#glow-red)"/>
    <text x="320" y="97" fill="#ef4444" font-family="monospace" font-size="10" text-anchor="middle">HIJACK: AS396982</text>

    <!-- Hop 4 Interception Node -->
    <circle cx="500" cy="75" r="7" fill="#ef4444" filter="url(#glow-red)"/>
    <text x="500" y="97" fill="#ef4444" font-family="monospace" font-size="10" text-anchor="middle">+94ms LATENCY</text>

    <!-- Destination -->
    <circle cx="1080" cy="40" r="8" fill="#00f2fe" filter="url(#glow-cyan)"/>
    <text x="1080" y="62" fill="#38bdf8" font-family="monospace" font-size="10" text-anchor="middle">1.1.1.1</text>
  </g>

  <!-- Capability Badges -->
  <g transform="translate(60, 345)">
    <!-- Badge 1: Compensation Word -->
    <rect x="0" y="0" width="250" height="36" rx="6" fill="#111827" stroke="#223352" stroke-width="1.2"/>
    <text x="14" y="23" fill="#00f2fe" font-family="monospace" font-size="12" font-weight="700">RFC 1071</text>
    <text x="85" y="23" fill="#cbd5e1" font-family="'JetBrains Mono', sans-serif" font-size="12" font-weight="500">Compensation Word</text>

    <!-- Badge 2: Jitter -->
    <rect x="270" y="0" width="255" height="36" rx="6" fill="#111827" stroke="#223352" stroke-width="1.2"/>
    <text x="284" y="23" fill="#38bdf8" font-family="monospace" font-size="12" font-weight="700">RFC 3550</text>
    <text x="355" y="23" fill="#cbd5e1" font-family="'JetBrains Mono', sans-serif" font-size="12" font-weight="500">EWMA Jitter Filter</text>

    <!-- Badge 3: Welford -->
    <rect x="545" y="0" width="255" height="36" rx="6" fill="#111827" stroke="#223352" stroke-width="1.2"/>
    <text x="559" y="23" fill="#10b981" font-family="monospace" font-size="12" font-weight="700">WELFORD</text>
    <text x="630" y="23" fill="#cbd5e1" font-family="'JetBrains Mono', sans-serif" font-size="12" font-weight="500">Stable Online s²</text>

    <!-- Badge 4: BGP Hijack -->
    <rect x="820" y="0" width="260" height="36" rx="6" fill="#111827" stroke="#223352" stroke-width="1.2"/>
    <text x="834" y="23" fill="#ef4444" font-family="monospace" font-size="12" font-weight="700">BGP GATE</text>
    <text x="912" y="23" fill="#cbd5e1" font-family="'JetBrains Mono', sans-serif" font-size="12" font-weight="500">ASN Path Reroute</text>
  </g>
</svg>
EOF

echo "[ASSETS] Generating preview.png via ImageMagick..."
magick -density 150 "${ASSETS_DIR}/banner.svg" "${ASSETS_DIR}/preview.png"
magick "${ASSETS_DIR}/preview.png" -strip "${ASSETS_DIR}/preview.png"

echo "[ASSETS] Generating demo.gif terminal session frames..."
TMP_DIR=$(mktemp -d)

# Frame 1: Terminal prompt
magick -size 920x440 xc:"#0a0f1d" \
  -fill "#1e293b" -draw "rectangle 0,0 920,34" \
  -fill "#ff5f56" -draw "circle 18,17 18,22" \
  -fill "#ffbd2e" -draw "circle 36,17 36,22" \
  -fill "#27c93f" -draw "circle 54,17 54,22" \
  -fill "#94a3b8" -font "DejaVu-Sans-Mono" -pointsize 13 -annotate +340+22 "tracegrid — bash — 920x440" \
  -fill "#00f2fe" -font "DejaVu-Sans-Mono" -pointsize 13 -annotate +25+68 "$ tracegrid probe --target 1.1.1.1 --protocol icmp --flow-id 1" \
  -strip "${TMP_DIR}/f1.png"

# Frame 2: Live hop results
magick "${TMP_DIR}/f1.png" \
  -fill "#f8fafc" -font "DejaVu-Sans-Mono" -pointsize 12 \
  -annotate +25+100 "TTL  IP ADDRESS         ASN / ORGANIZATION       LOSS%%     RTT (AVG)  JITTER     SPARK" \
  -fill "#334155" -font "DejaVu-Sans-Mono" -pointsize 12 \
  -annotate +25+115 "--------------------------------------------------------------------------------" \
  -fill "#cbd5e1" -font "DejaVu-Sans-Mono" -pointsize 12 \
  -annotate +25+135 "1    192.0.2.1          AS--- [Unannounced]      0.0%%      1.85 ms    0.05 ms     ▄█" \
  -annotate +25+155 "2    198.51.100.1       AS64496 EDGE-TRANSIT     0.0%%      4.21 ms    0.08 ms     ▅█" \
  -annotate +25+175 "3    203.0.113.10       AS174 COGENT-CORE        0.0%%      9.38 ms    0.12 ms     ▄█" \
  -annotate +25+195 "4    154.54.40.105      AS174 COGENT-CORE        0.0%%      14.15 ms   0.10 ms     ▅█" \
  -annotate +25+215 "5    1.1.1.1            AS13335 CLOUDFLARENET    0.0%%      23.28 ms   0.09 ms     ▄█" \
  -strip "${TMP_DIR}/f2.png"

# Frame 3: Diff Command
magick "${TMP_DIR}/f2.png" \
  -fill "#00f2fe" -font "DejaVu-Sans-Mono" -pointsize 13 \
  -annotate +25+250 "$ tracegrid diff fixtures/ecmp_route_run1.json fixtures/bgp_hijack_run2.json" \
  -strip "${TMP_DIR}/f3.png"

# Frame 4: Anomaly Alert & Hijack Verdict
magick "${TMP_DIR}/f3.png" \
  -fill "#f85149" -font "DejaVu-Sans-Mono" -pointsize 12 \
  -annotate +25+280 "[CRITICAL ALERT] BGP ASN Hijack Detected!" \
  -fill "#cbd5e1" -font "DejaVu-Sans-Mono" -pointsize 12 \
  -annotate +25+300 "  Baseline ASN Path : [64496, 174, 13335]" \
  -fill "#fb7185" -font "DejaVu-Sans-Mono" -pointsize 12 \
  -annotate +25+320 "  Active ASN Path   : [64496, 174, 396982, 13335] -> Diverged via AS396982 ROGUE-TRANSIT" \
  -fill "#f59e0b" -font "DejaVu-Sans-Mono" -pointsize 12 \
  -annotate +25+340 "  Latency Divergence: +93.9 ms spike at hop 6 | Risk Score: 100/100" \
  -fill "#00f2fe" -font "DejaVu-Sans-Mono" -pointsize 12 \
  -annotate +25+375 "[STATUS] Exported Dark-Mode Topology SVG | Zero Leaks Gate Verified" \
  -strip "${TMP_DIR}/f4.png"

echo "[ASSETS] Compiling demo.gif..."
magick -delay 160 "${TMP_DIR}/f1.png" \
       -delay 180 "${TMP_DIR}/f2.png" \
       -delay 160 "${TMP_DIR}/f3.png" \
       -delay 350 "${TMP_DIR}/f4.png" \
       -loop 0 "${ASSETS_DIR}/demo.gif"
magick "${ASSETS_DIR}/demo.gif" -strip "${ASSETS_DIR}/demo.gif"

rm -rf "${TMP_DIR}"

echo "[ASSETS] Verification:"
ls -lh "${ASSETS_DIR}"
