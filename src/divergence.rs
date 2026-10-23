// ==============================================================================
// Tracegrid: src/divergence.rs
// BGP ASN Path Analyzer, Route-Flap Detector & Latency Divergence Engine
// ==============================================================================

use crate::paris::ProbeProtocol;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// An individual hop telemetry record within a traceroute run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceHop {
    pub ttl: u8,
    pub ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub asn: Option<u32>,
    pub as_name: Option<String>,
    pub rtt_ms: Vec<f64>,
    pub loss_percent: f64,
    pub jitter_ms: f64,
    pub responding: bool,
}

impl TraceHop {
    /// Computes mean round-trip latency for responding probes.
    pub fn mean_rtt(&self) -> Option<f64> {
        if self.rtt_ms.is_empty() {
            None
        } else {
            let sum: f64 = self.rtt_ms.iter().sum();
            Some(sum / self.rtt_ms.len() as f64)
        }
    }

    /// Formats ASN tag (e.g. "AS15169 GOOGLE" or "AS--- [Unannounced]").
    pub fn asn_label(&self) -> String {
        match (self.asn, &self.as_name) {
            (Some(asn), Some(name)) => format!("AS{} {}", asn, name),
            (Some(asn), None) => format!("AS{}", asn),
            (None, _) => "AS--- [Unannounced]".to_string(),
        }
    }
}

/// A complete traceroute measurement run against a destination target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceRun {
    pub target: String,
    pub target_ip: Ipv4Addr,
    pub timestamp: String,
    pub protocol: ProbeProtocol,
    pub flow_id: u16,
    pub hops: Vec<TraceHop>,
    pub completed: bool,
}

impl TraceRun {
    /// Extracts the compressed BGP ASN path sequence (removing adjacent duplicate ASNs).
    pub fn asn_sequence(&self) -> Vec<u32> {
        let mut path = Vec::new();
        for hop in &self.hops {
            if let Some(asn) = hop.asn {
                if path.last() != Some(&asn) {
                    path.push(asn);
                }
            }
        }
        path
    }
}

/// Classification of route anomalies and divergence types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceType {
    Unchanged,
    AsnHijack,
    RouteFlap,
    EcmpBranch,
    IpChanged,
    LatencySpike,
    PacketLossSpike,
    MissingHop,
    NewHop,
}

/// Severity level of detected routing anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Critical => write!(f, "CRIT"),
        }
    }
}

/// Diff analysis between a baseline hop and an active hop at the same TTL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HopDiff {
    pub ttl: u8,
    pub divergence_type: DivergenceType,
    pub severity: Severity,
    pub description: String,
    pub baseline_hop: Option<TraceHop>,
    pub active_hop: Option<TraceHop>,
    pub latency_delta_ms: f64,
}

/// Comprehensive route diffing and security divergence report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DivergenceReport {
    pub target: String,
    pub baseline_timestamp: String,
    pub active_timestamp: String,
    pub baseline_asn_path: Vec<u32>,
    pub active_asn_path: Vec<u32>,
    pub is_asn_path_divergent: bool,
    pub detected_hijack: bool,
    pub detected_flaps: bool,
    pub max_latency_spike_ms: f64,
    pub risk_score: u32,
    pub diffs: Vec<HopDiff>,
    pub summary: String,
}

/// Route Divergence and BGP Hijack Analysis Engine.
#[derive(Debug, Clone)]
pub struct RouteDivergenceEngine {
    pub latency_spike_threshold_ms: f64,
    pub loss_spike_threshold_pct: f64,
}

impl Default for RouteDivergenceEngine {
    fn default() -> Self {
        Self::new(25.0, 30.0)
    }
}

impl RouteDivergenceEngine {
    /// Creates a new analysis engine with specified thresholds.
    pub fn new(latency_spike_threshold_ms: f64, loss_spike_threshold_pct: f64) -> Self {
        Self {
            latency_spike_threshold_ms,
            loss_spike_threshold_pct,
        }
    }

    /// Compares a baseline trace with an active trace to detect hijacks, flaps, and spikes.
    pub fn analyze(&self, baseline: &TraceRun, active: &TraceRun) -> DivergenceReport {
        let max_ttl = baseline
            .hops
            .iter()
            .map(|h| h.ttl)
            .chain(active.hops.iter().map(|h| h.ttl))
            .max()
            .unwrap_or(0);

        let mut diffs = Vec::new();
        let mut detected_hijack = false;
        let mut detected_flaps = false;
        let mut max_latency_spike_ms = 0.0f64;
        let mut total_risk_points = 0u32;

        for ttl in 1..=max_ttl {
            let b_hop = baseline.hops.iter().find(|h| h.ttl == ttl).cloned();
            let a_hop = active.hops.iter().find(|h| h.ttl == ttl).cloned();

            match (&b_hop, &a_hop) {
                (Some(b), Some(a)) => {
                    let b_rtt = b.mean_rtt().unwrap_or(0.0);
                    let a_rtt = a.mean_rtt().unwrap_or(0.0);
                    let delta_rtt = a_rtt - b_rtt;
                    if delta_rtt > max_latency_spike_ms {
                        max_latency_spike_ms = delta_rtt;
                    }

                    // 1. Check for BGP ASN Hijack / Divergence
                    if b.asn != a.asn && (b.asn.is_some() || a.asn.is_some()) {
                        let b_asn_str = b.asn.map(|x| format!("AS{}", x)).unwrap_or_else(|| "none".to_string());
                        let a_asn_str = a.asn.map(|x| format!("AS{}", x)).unwrap_or_else(|| "none".to_string());

                        // If destination hop or intermediate hop changed to an unexpected external AS
                        detected_hijack = true;
                        total_risk_points += 50;
                        diffs.push(HopDiff {
                            ttl,
                            divergence_type: DivergenceType::AsnHijack,
                            severity: Severity::Critical,
                            description: format!(
                                "BGP ASN divergence at hop {}: baseline {} diverted to active {}",
                                ttl, b_asn_str, a_asn_str
                            ),
                            baseline_hop: Some(b.clone()),
                            active_hop: Some(a.clone()),
                            latency_delta_ms: delta_rtt,
                        });
                        continue;
                    }

                    // 2. Check for IP changed (ECMP vs Unstable flap)
                    if b.ip != a.ip {
                        if b.asn == a.asn && b.asn.is_some() {
                            // Intra-AS ECMP route change
                            diffs.push(HopDiff {
                                ttl,
                                divergence_type: DivergenceType::EcmpBranch,
                                severity: Severity::Info,
                                description: format!(
                                    "Intra-AS ECMP path variation at hop {}: {:?} -> {:?}",
                                    ttl, b.ip, a.ip
                                ),
                                baseline_hop: Some(b.clone()),
                                active_hop: Some(a.clone()),
                                latency_delta_ms: delta_rtt,
                            });
                        } else {
                            detected_flaps = true;
                            total_risk_points += 20;
                            diffs.push(HopDiff {
                                ttl,
                                divergence_type: DivergenceType::RouteFlap,
                                severity: Severity::Warning,
                                description: format!(
                                    "Route flap/re-route at hop {}: {:?} -> {:?}",
                                    ttl, b.ip, a.ip
                                ),
                                baseline_hop: Some(b.clone()),
                                active_hop: Some(a.clone()),
                                latency_delta_ms: delta_rtt,
                            });
                        }
                    }

                    // 3. Check for severe packet loss spike
                    let loss_delta = a.loss_percent - b.loss_percent;
                    if loss_delta >= self.loss_spike_threshold_pct {
                        total_risk_points += 25;
                        diffs.push(HopDiff {
                            ttl,
                            divergence_type: DivergenceType::PacketLossSpike,
                            severity: Severity::Warning,
                            description: format!(
                                "Packet loss surge at hop {}: {:.1}% -> {:.1}% (+{:.1}%)",
                                ttl, b.loss_percent, a.loss_percent, loss_delta
                            ),
                            baseline_hop: Some(b.clone()),
                            active_hop: Some(a.clone()),
                            latency_delta_ms: delta_rtt,
                        });
                    }

                    // 4. Check for latency spike
                    if delta_rtt >= self.latency_spike_threshold_ms {
                        let severity = if delta_rtt > 50.0 {
                            total_risk_points += 30;
                            Severity::Critical
                        } else {
                            total_risk_points += 15;
                            Severity::Warning
                        };

                        diffs.push(HopDiff {
                            ttl,
                            divergence_type: DivergenceType::LatencySpike,
                            severity,
                            description: format!(
                                "Latency spike at hop {}: baseline {:.2}ms -> active {:.2}ms (+{:.2}ms)",
                                ttl, b_rtt, a_rtt, delta_rtt
                            ),
                            baseline_hop: Some(b.clone()),
                            active_hop: Some(a.clone()),
                            latency_delta_ms: delta_rtt,
                        });
                    }

                    // If identical and healthy
                    if b.ip == a.ip && b.asn == a.asn && delta_rtt.abs() < self.latency_spike_threshold_ms && loss_delta < self.loss_spike_threshold_pct {
                        diffs.push(HopDiff {
                            ttl,
                            divergence_type: DivergenceType::Unchanged,
                            severity: Severity::Info,
                            description: format!("Hop {} stable ({:?}, {:.2}ms)", ttl, b.ip, a_rtt),
                            baseline_hop: Some(b.clone()),
                            active_hop: Some(a.clone()),
                            latency_delta_ms: delta_rtt,
                        });
                    }
                }
                (Some(b), None) => {
                    total_risk_points += 20;
                    diffs.push(HopDiff {
                        ttl,
                        divergence_type: DivergenceType::MissingHop,
                        severity: Severity::Warning,
                        description: format!("Hop {} dropped in active trace (baseline was {:?})", ttl, b.ip),
                        baseline_hop: Some(b.clone()),
                        active_hop: None,
                        latency_delta_ms: 0.0,
                    });
                }
                (None, Some(a)) => {
                    diffs.push(HopDiff {
                        ttl,
                        divergence_type: DivergenceType::NewHop,
                        severity: Severity::Info,
                        description: format!("New hop {} observed in active trace ({:?})", ttl, a.ip),
                        baseline_hop: None,
                        active_hop: Some(a.clone()),
                        latency_delta_ms: 0.0,
                    });
                }
                (None, None) => {}
            }
        }

        let baseline_path = baseline.asn_sequence();
        let active_path = active.asn_sequence();
        let is_asn_path_divergent = baseline_path != active_path;

        let risk_score = total_risk_points.min(100);

        let summary = if detected_hijack {
            format!(
                "CRITICAL: BGP ASN path hijacking detected! Active trace diverged from baseline ASN path {:?} to {:?}. Risk score: {}/100",
                baseline_path, active_path, risk_score
            )
        } else if detected_flaps || max_latency_spike_ms >= self.latency_spike_threshold_ms {
            format!(
                "WARNING: Route instability detected. Max latency delta: +{:.2}ms. Risk score: {}/100",
                max_latency_spike_ms, risk_score
            )
        } else {
            format!(
                "STABLE: Active trace conforms to baseline topology across all {} hops. Risk score: 0/100",
                baseline.hops.len()
            )
        };

        DivergenceReport {
            target: baseline.target.clone(),
            baseline_timestamp: baseline.timestamp.clone(),
            active_timestamp: active.timestamp.clone(),
            baseline_asn_path: baseline_path,
            active_asn_path: active_path,
            is_asn_path_divergent,
            detected_hijack,
            detected_flaps,
            max_latency_spike_ms,
            risk_score,
            diffs,
            summary,
        }
    }
}
