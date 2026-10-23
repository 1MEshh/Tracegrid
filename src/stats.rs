// ==============================================================================
// Tracegrid: src/stats.rs
// Welford's Online Numerical Statistics & RFC 3550 Inter-Arrival Jitter Engine
// ==============================================================================

use serde::{Deserialize, Serialize};

/// Welford's algorithm for numerically stable running mean and sample variance.
/// Prevents catastrophic cancellation of floating-point arithmetic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelfordStats {
    pub count: usize,
    pub mean: f64,
    pub m2: f64,
    pub min: f64,
    pub max: f64,
    pub samples: Vec<f64>,
}

impl Default for WelfordStats {
    fn default() -> Self {
        Self::new()
    }
}

impl WelfordStats {
    /// Creates a new empty WelfordStats accumulator.
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            samples: Vec::new(),
        }
    }

    /// Feeds a new numerical observation x_k into the accumulator.
    pub fn update(&mut self, x: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / (self.count as f64);
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;

        if x < self.min {
            self.min = x;
        }
        if x > self.max {
            self.max = x;
        }
        self.samples.push(x);
    }

    /// Computes unbiased sample variance s^2 = M_2 / (n - 1) for n >= 2.
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / ((self.count - 1) as f64)
        }
    }

    /// Computes sample standard deviation s = sqrt(s^2).
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Computes population variance sigma^2 = M_2 / n.
    pub fn population_variance(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.m2 / (self.count as f64)
        }
    }

    /// Computes the p-th percentile (0.0 <= p <= 100.0) from collected samples.
    pub fn percentile(&self, p: f64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let clamped_p = p.clamp(0.0, 100.0);
        let rank = (clamped_p / 100.0) * ((sorted.len() - 1) as f64);
        let lower = rank.floor() as usize;
        let upper = rank.ceil() as usize;
        let frac = rank - (lower as f64);

        if lower == upper || upper >= sorted.len() {
            sorted[lower]
        } else {
            sorted[lower] * (1.0 - frac) + sorted[upper] * frac
        }
    }
}

/// RFC 3550 Inter-Arrival Jitter Estimator (RTP specification section 6.4.1).
/// Implements continuous Exponentially Weighted Moving Average (EWMA) filter:
/// J_i = J_{i-1} + (|D(i-1, i)| - J_{i-1}) / 16
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc3550Jitter {
    pub jitter: f64,
    pub prev_transit_time: Option<f64>,
    pub update_count: usize,
}

impl Default for Rfc3550Jitter {
    fn default() -> Self {
        Self::new()
    }
}

impl Rfc3550Jitter {
    /// Creates a new RFC 3550 jitter filter.
    pub fn new() -> Self {
        Self {
            jitter: 0.0,
            prev_transit_time: None,
            update_count: 0,
        }
    }

    /// Updates running jitter with one-way or round-trip transit delay (in milliseconds).
    /// D(i-1, i) = transit_i - transit_{i-1}
    pub fn update_transit(&mut self, transit_time_ms: f64) -> f64 {
        if let Some(prev) = self.prev_transit_time {
            let d = (transit_time_ms - prev).abs();
            self.jitter += (d - self.jitter) / 16.0;
            self.update_count += 1;
        }
        self.prev_transit_time = Some(transit_time_ms);
        self.jitter
    }

    /// Updates running jitter using explicit send and receive timestamps.
    /// Transit = recv_ts - send_ts.
    pub fn update_timestamps(&mut self, send_ts_ms: f64, recv_ts_ms: f64) -> f64 {
        let transit = recv_ts_ms - send_ts_ms;
        self.update_transit(transit)
    }

    /// Returns the current RFC 3550 jitter estimate in milliseconds.
    pub fn current_jitter(&self) -> f64 {
        self.jitter
    }
}

/// Hop telemetry aggregating packet loss, Welford latency stats, and RFC 3550 jitter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopTelemetry {
    pub ttl: u8,
    pub probes_sent: usize,
    pub probes_received: usize,
    pub latency_stats: WelfordStats,
    pub jitter_filter: Rfc3550Jitter,
}

impl HopTelemetry {
    /// Creates a new HopTelemetry record for given TTL.
    pub fn new(ttl: u8) -> Self {
        Self {
            ttl,
            probes_sent: 0,
            probes_received: 0,
            latency_stats: WelfordStats::new(),
            jitter_filter: Rfc3550Jitter::new(),
        }
    }

    /// Records a probe dispatch.
    pub fn record_sent(&mut self) {
        self.probes_sent += 1;
    }

    /// Records a probe response with measured round-trip time in milliseconds.
    pub fn record_reply(&mut self, rtt_ms: f64) {
        self.probes_received += 1;
        self.latency_stats.update(rtt_ms);
        self.jitter_filter.update_transit(rtt_ms);
    }

    /// Calculates packet loss percentage (0.0% to 100.0%).
    pub fn packet_loss_percent(&self) -> f64 {
        if self.probes_sent == 0 {
            0.0
        } else {
            let lost = self.probes_sent.saturating_sub(self.probes_received);
            (lost as f64 / self.probes_sent as f64) * 100.0
        }
    }
}

/// Renders a compact terminal sparkline from a numerical series using Unicode block elements.
pub fn render_sparkline(values: &[f64]) -> String {
    if values.is_empty() {
        return "·".to_string();
    }

    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);

    let bars = [' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let range = max - min;

    let mut result = String::with_capacity(values.len());
    for &v in values {
        let index = if range <= 1e-9 {
            3 // Mid-level line if all values are equal
        } else {
            let norm = ((v - min) / range).clamp(0.0, 1.0);
            let idx = (norm * ((bars.len() - 1) as f64)).round() as usize;
            idx.min(bars.len() - 1)
        };
        result.push(bars[index]);
    }
    result
}
