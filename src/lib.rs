// ==============================================================================
// Tracegrid: src/lib.rs
// High-Performance Paris-Traceroute & Route Divergence Engine
// ==============================================================================

pub mod paris;
pub mod stats;

pub use paris::{InternetChecksum, ParisFlow, ParisProbePacket, ProbeProtocol};
pub use stats::{render_sparkline, HopTelemetry, Rfc3550Jitter, WelfordStats};
