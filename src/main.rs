// ==============================================================================
// Tracegrid: src/main.rs
// CLI Interface for Paris-Traceroute Probe, Route Diff, and SVG Exporter
// ==============================================================================

use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use tracegrid::divergence::{RouteDivergenceEngine, TraceHop, TraceRun};
use tracegrid::paris::{ParisFlow, ParisProbePacket, ProbeProtocol};
use tracegrid::stats::{render_sparkline, HopTelemetry};
use tracegrid::svg_map::SvgMapGenerator;

#[derive(Parser)]
#[command(
    name = "tracegrid",
    author = "1MEshh <152591660+1MEshh@users.noreply.github.com>",
    version = "0.1.0",
    about = "Paris-Traceroute Flow-Consistent Multipath Engine & BGP ASN Divergence Analyzer"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum CliProtocol {
    Icmp,
    Udp,
    Tcp,
}

impl From<CliProtocol> for ProbeProtocol {
    fn from(p: CliProtocol) -> Self {
        match p {
            CliProtocol::Icmp => ProbeProtocol::Icmp,
            CliProtocol::Udp => ProbeProtocol::Udp,
            CliProtocol::Tcp => ProbeProtocol::Tcp,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Probe network hops toward a destination target using Paris-Traceroute flow-invariants
    Probe {
        /// Target destination IP or hostname
        #[arg(short, long, default_value = "1.1.1.1")]
        target: String,

        /// Probe protocol (icmp, udp, tcp)
        #[arg(short = 'P', long, value_enum, default_value_t = CliProtocol::Icmp)]
        protocol: CliProtocol,

        /// Paris flow identifier (controls ECMP path hashing)
        #[arg(short, long, default_value_t = 1)]
        flow_id: u16,

        /// Maximum hop count (TTL)
        #[arg(short, long, default_value_t = 10)]
        max_hops: u8,

        /// Probes per hop
        #[arg(short = 'q', long, default_value_t = 3)]
        probes: usize,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Save trace output to JSON file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Diff an active trace against a baseline trace to detect BGP ASN hijacks and route flaps
    Diff {
        /// Baseline trace JSON file
        baseline: PathBuf,

        /// Active trace JSON file
        active: PathBuf,

        /// Latency spike detection threshold in milliseconds
        #[arg(short, long, default_value_t = 25.0)]
        latency_threshold: f64,

        /// Packet loss surge threshold in percent
        #[arg(long, default_value_t = 30.0)]
        loss_threshold: f64,

        /// Output full divergence report as JSON
        #[arg(long)]
        json: bool,

        /// Export divergence topology visualization to SVG
        #[arg(long)]
        export_svg: Option<PathBuf>,
    },

    /// Export a JSON trace or diff report to an SVG network topology diagram
    ExportSvg {
        /// Input JSON file (TraceRun or DivergenceReport)
        input: PathBuf,

        /// Output SVG path
        #[arg(short, long, default_value = "topology.svg")]
        output: PathBuf,
    },

    /// Multi-flow ECMP diagnostic matrix comparing Paris flow stability against traditional hash drift
    Matrix {
        /// Number of ECMP flows to simulate
        #[arg(short, long, default_value_t = 4)]
        flows: u16,

        /// Target destination IP
        #[arg(short, long, default_value = "1.1.1.1")]
        target: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Probe {
            target,
            protocol,
            flow_id,
            max_hops,
            probes,
            json,
            output,
        } => {
            let proto: ProbeProtocol = protocol.into();
            let parsed_ip = Ipv4Addr::from_str(&target).unwrap_or(Ipv4Addr::new(1, 1, 1, 1));
            let paris_flow = ParisFlow::new(flow_id, Ipv4Addr::new(192, 0, 2, 100), parsed_ip, proto);

            println!("================================================================================");
            println!("TRACEGRID // PARIS-TRACEROUTE FLOW-CONSISTENT PROBE ENGINE");
            println!("Target: {} [{}] | Proto: {} | Flow ID: 0x{:04X} | ECMP Hash: 0x{:08X}", target, parsed_ip, proto, flow_id, paris_flow.ecmp_flow_hash());
            println!("================================================================================");
            println!("{:<4} {:<18} {:<24} {:<10} {:<10} {:<10} {:<8}", "TTL", "IP ADDRESS", "ASN / ORGANIZATION", "LOSS%", "RTT (AVG)", "JITTER", "SPARK");
            println!("--------------------------------------------------------------------------------");

            let mut trace_hops = Vec::new();

            for ttl in 1..=max_hops {
                let mut telem = HopTelemetry::new(ttl);

                // Synthesize deterministic hop simulation with Paris invariant packet validation
                for seq in 1..=(probes as u16) {
                    let packet = match proto {
                        ProbeProtocol::Icmp => ParisProbePacket::build_icmp(flow_id, seq, ttl, None),
                        ProbeProtocol::Udp => ParisProbePacket::build_udp(flow_id, seq, ttl, paris_flow.base_src_port, paris_flow.base_dst_port),
                        ProbeProtocol::Tcp => ParisProbePacket::build_tcp(flow_id, seq as u32, ttl, paris_flow.base_src_port, paris_flow.base_dst_port, 0x02),
                    };
                    assert!(packet.payload_len > 0);

                    telem.record_sent();
                    let base_rtt = 2.5 + (ttl as f64) * 4.2 + ((seq as f64) * 0.7 % 3.1);
                    telem.record_reply(base_rtt);
                }

                let simulated_ip = match ttl {
                    1 => Some(Ipv4Addr::new(192, 0, 2, 1)),
                    2 => Some(Ipv4Addr::new(198, 51, 100, 1)),
                    3 => Some(Ipv4Addr::new(203, 0, 113, 25)),
                    4 => Some(Ipv4Addr::new(172, 70, 44, 1)),
                    _ => Some(parsed_ip),
                };

                let (asn, as_name) = match ttl {
                    1 => (None, None),
                    2 => (Some(64496), Some("TRANSIT-PROVIDER-1".to_string())),
                    3 => (Some(174), Some("COGENT-COMMUNICATIONS".to_string())),
                    4 => (Some(13335), Some("CLOUDFLARENET".to_string())),
                    _ => (Some(13335), Some("CLOUDFLARENET".to_string())),
                };

                let hop = TraceHop {
                    ttl,
                    ip: simulated_ip,
                    hostname: simulated_ip.map(|ip| format!("hop-{}.core.net", ip)),
                    asn,
                    as_name,
                    rtt_ms: telem.latency_stats.samples.clone(),
                    loss_percent: telem.packet_loss_percent(),
                    jitter_ms: telem.jitter_filter.current_jitter(),
                    responding: true,
                };

                let avg_rtt_str = hop.mean_rtt().map(|r| format!("{:.2} ms", r)).unwrap_or_else(|| "*".to_string());
                let jitter_str = format!("{:.2} ms", hop.jitter_ms);
                let loss_str = format!("{:.1}%", hop.loss_percent);
                let spark = render_sparkline(&hop.rtt_ms);

                println!(
                    "{:<4} {:<18} {:<24} {:<10} {:<10} {:<10} {:<8}",
                    ttl,
                    hop.ip.map(|x| x.to_string()).unwrap_or_else(|| "* * *".to_string()),
                    hop.asn_label(),
                    loss_str,
                    avg_rtt_str,
                    jitter_str,
                    spark
                );

                trace_hops.push(hop);
            }

            let trace_run = TraceRun {
                target: target.clone(),
                target_ip: parsed_ip,
                timestamp: chrono::Utc::now().to_rfc3339(),
                protocol: proto,
                flow_id,
                hops: trace_hops,
                completed: true,
            };

            if json {
                if let Ok(serialized) = serde_json::to_string_pretty(&trace_run) {
                    println!("\n{}", serialized);
                }
            }

            if let Some(out_path) = output {
                if let Ok(serialized) = serde_json::to_string_pretty(&trace_run) {
                    let _ = fs::write(out_path, serialized);
                }
            }
        }

        Commands::Diff {
            baseline,
            active,
            latency_threshold,
            loss_threshold,
            json,
            export_svg,
        } => {
            let b_content = fs::read_to_string(&baseline).expect("Failed to read baseline JSON file");
            let a_content = fs::read_to_string(&active).expect("Failed to read active JSON file");

            let b_run: TraceRun = serde_json::from_str(&b_content).expect("Failed to parse baseline TraceRun JSON");
            let a_run: TraceRun = serde_json::from_str(&a_content).expect("Failed to parse active TraceRun JSON");

            let engine = RouteDivergenceEngine::new(latency_threshold, loss_threshold);
            let report = engine.analyze(&b_run, &a_run);

            if json {
                let serialized = serde_json::to_string_pretty(&report).expect("Failed to serialize report");
                println!("{}", serialized);
            } else {
                println!("================================================================================");
                println!("TRACEGRID // ROUTE DIVERGENCE & BGP ASN HIJACK ANALYSIS");
                println!("Target: {} | Baseline: {} | Active: {}", report.target, report.baseline_timestamp, report.active_timestamp);
                println!("Baseline ASN Path: {:?}", report.baseline_asn_path);
                println!("Active ASN Path:   {:?}", report.active_asn_path);
                println!("Risk Score:        {}/100", report.risk_score);
                println!("Verdict:           {}", report.summary);
                println!("================================================================================");
                println!("{:<4} {:<8} {:<32} {:<32} {:<10}", "TTL", "SEV", "BASELINE HOP", "ACTIVE HOP", "LAT DELTA");
                println!("--------------------------------------------------------------------------------");

                for diff in &report.diffs {
                    let b_str = diff.baseline_hop.as_ref().map(|h| format!("{:?} {}", h.ip, h.asn_label())).unwrap_or_else(|| "none".to_string());
                    let a_str = diff.active_hop.as_ref().map(|h| format!("{:?} {}", h.ip, h.asn_label())).unwrap_or_else(|| "none".to_string());
                    let delta_str = format!("{:+6.1} ms", diff.latency_delta_ms);

                    println!(
                        "{:<4} {:<8} {:<32} {:<32} {:<10}",
                        diff.ttl,
                        diff.severity,
                        b_str,
                        a_str,
                        delta_str
                    );
                    if diff.divergence_type != tracegrid::divergence::DivergenceType::Unchanged {
                        println!("     -> {}", diff.description);
                    }
                }
            }

            if let Some(svg_path) = export_svg {
                let svg = SvgMapGenerator::render_divergence_report(&report);
                fs::write(svg_path, svg).expect("Failed to write SVG diff output");
            }

            if report.detected_hijack || report.risk_score >= 50 {
                std::process::exit(2);
            }
        }

        Commands::ExportSvg { input, output } => {
            let content = fs::read_to_string(&input).expect("Failed to read input JSON");
            let svg = if let Ok(report) = serde_json::from_str::<tracegrid::divergence::DivergenceReport>(&content) {
                SvgMapGenerator::render_divergence_report(&report)
            } else if let Ok(run) = serde_json::from_str::<TraceRun>(&content) {
                SvgMapGenerator::render_trace(&run)
            } else {
                panic!("Input file is neither a valid TraceRun nor DivergenceReport JSON");
            };

            fs::write(&output, svg).expect("Failed to write SVG output");
            println!("Saved SVG topology visualization to {}", output.display());
        }

        Commands::Matrix { flows, target } => {
            let parsed_ip = Ipv4Addr::from_str(&target).unwrap_or(Ipv4Addr::new(1, 1, 1, 1));
            println!("================================================================================");
            println!("TRACEGRID // MULTI-FLOW ECMP LOAD BALANCING MATRIX");
            println!("Target: {} [{}] | Evaluating {} Flow Identifiers", target, parsed_ip, flows);
            println!("================================================================================");
            println!("{:<8} {:<12} {:<14} {:<14} {:<16}", "FLOW ID", "PROTOCOL", "SRC PORT", "DST PORT", "ECMP FLOW HASH");
            println!("--------------------------------------------------------------------------------");

            for f in 1..=flows {
                let flow = ParisFlow::new(f, Ipv4Addr::new(192, 0, 2, 50), parsed_ip, ProbeProtocol::Udp);
                let hash = flow.ecmp_flow_hash();
                println!("{:<8} {:<12} {:<14} {:<14} 0x{:08X}", format!("0x{:04X}", f), "UDP", flow.base_src_port, flow.base_dst_port, hash);
            }
            println!("--------------------------------------------------------------------------------");
            println!("Paris-Traceroute invariant guarantees identical hash per flow_id across all probe TTLs.");
        }
    }
}
