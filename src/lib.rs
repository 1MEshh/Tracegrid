// ==============================================================================
// Tracegrid: src/lib.rs
// High-Performance Paris-Traceroute & Route Divergence Engine
// ==============================================================================

pub mod divergence;
pub mod paris;
pub mod stats;
pub mod svg_map;

pub use divergence::{
    DivergenceReport, DivergenceType, HopDiff, RouteDivergenceEngine, Severity, TraceHop, TraceRun,
};
pub use paris::{InternetChecksum, ParisFlow, ParisProbePacket, ProbeProtocol};
pub use stats::{render_sparkline, HopTelemetry, Rfc3550Jitter, WelfordStats};
pub use svg_map::{escape_xml, SvgMapGenerator};
