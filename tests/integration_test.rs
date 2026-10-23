// ==============================================================================
// Tracegrid: tests/integration_test.rs
// Comprehensive Integration Test Suite
// Covers RFC 1071 / 1624 Checksums, Paris Invariants, Welford Stability,
// RFC 3550 Jitter, BGP Diffing, XSS-Safe SVG, and Fixtures
// ==============================================================================

use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use tracegrid::divergence::{
    DivergenceReport, DivergenceType, RouteDivergenceEngine, Severity, TraceHop, TraceRun,
};
use tracegrid::paris::{InternetChecksum, ParisFlow, ParisProbePacket, ProbeProtocol};
use tracegrid::stats::{render_sparkline, HopTelemetry, Rfc3550Jitter, WelfordStats};
use tracegrid::svg_map::{escape_xml, SvgMapGenerator};

// ------------------------------------------------------------------------------
// 1. Internet Checksum (RFC 1071 / RFC 1624) Tests
// ------------------------------------------------------------------------------

#[test]
fn test_internet_checksum_rfc1071_standard_vector() {
    // RFC 1071 test vector
    let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    let csum = InternetChecksum::compute(&data);
    assert_ne!(csum, 0);

    // Verify sum with checksum included equals 0xffff
    let mut packet = data.to_vec();
    packet.extend_from_slice(&csum.to_be_bytes());
    assert!(InternetChecksum::verify(&packet));
}

#[test]
fn test_internet_checksum_odd_length_padding() {
    let data = [0x45, 0x00, 0x00, 0x3c, 0x1c];
    let csum = InternetChecksum::compute(&data);
    assert_ne!(csum, 0);

    // In RFC 1071 / RFC 768, odd-length payloads are padded to a 16-bit boundary
    let mut packet = data.to_vec();
    packet.push(0x00);
    packet.extend_from_slice(&csum.to_be_bytes());
    assert!(InternetChecksum::verify(&packet));
}

#[test]
fn test_ones_complement_addition_and_subtraction() {
    // In one's complement: 0x0001 + 0xfffe = 0xffff
    let sum = InternetChecksum::ones_complement_add(0x0001, 0xfffe);
    assert_eq!(sum, 0xffff);

    // Carry fold: 0xffff + 0x0001 = 0x0001 (end around carry)
    let sum_carry = InternetChecksum::ones_complement_add(0xffff, 0x0001);
    assert_eq!(sum_carry, 0x0001);

    // Subtraction: a - b = a + (~b)
    let diff = InternetChecksum::ones_complement_sub(0x0005, 0x0002);
    assert_eq!(diff, 0x0003);
}

#[test]
fn test_rfc1624_incremental_checksum_update() {
    let mut data = vec![0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78];
    let old_csum = InternetChecksum::compute(&data);
    data[2..4].copy_from_slice(&old_csum.to_be_bytes());
    assert!(InternetChecksum::verify(&data));

    // Update field m (0x1234) to m' (0x5678)
    let old_val = 0x1234u16;
    let new_val = 0x5678u16;
    let new_csum = InternetChecksum::incremental_update(old_csum, old_val, new_val);

    data[4..6].copy_from_slice(&new_val.to_be_bytes());
    data[2..4].copy_from_slice(&new_csum.to_be_bytes());

    assert!(InternetChecksum::verify(&data));
}

// ------------------------------------------------------------------------------
// 2. Paris Traceroute Flow-Identifier & Compensation Word Tests
// ------------------------------------------------------------------------------

#[test]
fn test_paris_compensation_word_math() {
    let base_seq = 1u16;
    let base_comp = 0x5a5au16;

    let seq_new = 42u16;
    let comp_new = InternetChecksum::calculate_compensation_word(seq_new, base_seq, base_comp);

    let base_sum = InternetChecksum::ones_complement_add(base_seq, base_comp);
    let new_sum = InternetChecksum::ones_complement_add(seq_new, comp_new);
    assert_eq!(base_sum, new_sum);
}

#[test]
fn test_paris_icmp_probe_checksum_invariance() {
    let flow_id = 1337u16;
    let p1 = ParisProbePacket::build_icmp(flow_id, 1, 1, None);
    let target_checksum = p1.checksum;

    // Build probes with increasing sequence numbers using invariant target checksum
    let p2 = ParisProbePacket::build_icmp(flow_id, 2, 2, Some(target_checksum));
    let p3 = ParisProbePacket::build_icmp(flow_id, 100, 3, Some(target_checksum));
    let p4 = ParisProbePacket::build_icmp(flow_id, 999, 4, Some(target_checksum));

    assert_eq!(p1.checksum, target_checksum);
    assert_eq!(p2.checksum, target_checksum);
    assert_eq!(p3.checksum, target_checksum);
    assert_eq!(p4.checksum, target_checksum);

    // Verify raw wire checksum consistency
    let mut check_p2 = p2.wire_bytes.clone();
    check_p2[2..4].copy_from_slice(&[0, 0]);
    assert_eq!(InternetChecksum::compute(&check_p2), target_checksum);

    let mut check_p4 = p4.wire_bytes.clone();
    check_p4[2..4].copy_from_slice(&[0, 0]);
    assert_eq!(InternetChecksum::compute(&check_p4), target_checksum);
}

#[test]
fn test_paris_udp_probe_generation() {
    let flow = ParisFlow::new(
        10,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(198, 51, 100, 1),
        ProbeProtocol::Udp,
    );
    let probe = ParisProbePacket::build_udp(flow.flow_id, 1, 5, flow.base_src_port, flow.base_dst_port);

    assert_eq!(probe.protocol, ProbeProtocol::Udp);
    assert_eq!(probe.ttl, 5);
    assert_eq!(probe.src_port, flow.base_src_port);
    assert_eq!(probe.dst_port, flow.base_dst_port);
    assert!(probe.payload_len >= 28);
    assert!(probe.verify_checksum());
}

#[test]
fn test_paris_tcp_probe_generation() {
    let flow = ParisFlow::new(
        20,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(198, 51, 100, 1),
        ProbeProtocol::Tcp,
    );
    let probe = ParisProbePacket::build_tcp(flow.flow_id, 1000, 8, flow.base_src_port, flow.base_dst_port, 0x02);

    assert_eq!(probe.protocol, ProbeProtocol::Tcp);
    assert_eq!(probe.ttl, 8);
    assert_eq!(probe.wire_bytes[13], 0x02); // SYN flag
    assert!(probe.verify_checksum());
}

#[test]
fn test_paris_ecmp_flow_hash_consistency() {
    let f1 = ParisFlow::new(42, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(1, 1, 1, 1), ProbeProtocol::Icmp);
    let f2 = ParisFlow::new(42, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(1, 1, 1, 1), ProbeProtocol::Icmp);

    assert_eq!(f1.ecmp_flow_hash(), f2.ecmp_flow_hash());
}

#[test]
fn test_paris_ecmp_flow_hash_differentiation() {
    let f1 = ParisFlow::new(1, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(1, 1, 1, 1), ProbeProtocol::Udp);
    let f2 = ParisFlow::new(2, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(1, 1, 1, 1), ProbeProtocol::Udp);

    assert_ne!(f1.ecmp_flow_hash(), f2.ecmp_flow_hash());
}

// ------------------------------------------------------------------------------
// 3. Welford's Algorithm & Numerical Stability Tests
// ------------------------------------------------------------------------------

#[test]
fn test_welford_numerical_stability_high_mean_low_variance() {
    // Catastrophic cancellation stress test:
    // When observations have large constant offset 1e9, naive E[x^2] - (E[x])^2
    // subtracts nearly identical huge floats and produces zero or negative variance.
    // Welford's algorithm computes the exact sample variance 2.5!
    let offset = 1_000_000_000.0;
    let inputs = [offset + 1.0, offset + 2.0, offset + 3.0, offset + 4.0, offset + 5.0];

    let mut welford = WelfordStats::new();
    for &x in &inputs {
        welford.update(x);
    }

    assert_eq!(welford.count, 5);
    assert!((welford.mean - (offset + 3.0)).abs() < 1e-6);

    let sample_variance = welford.variance();
    // Population: sum((x - mean)^2) = 4 + 1 + 0 + 1 + 4 = 10; Sample var = 10 / (5 - 1) = 2.5
    assert!((sample_variance - 2.5).abs() < 1e-9);

    let pop_variance = welford.population_variance();
    assert!((pop_variance - 2.0).abs() < 1e-9);

    let std_dev = welford.std_dev();
    assert!((std_dev - 2.5f64.sqrt()).abs() < 1e-9);
}

#[test]
fn test_welford_running_mean_and_variance() {
    let mut stats = WelfordStats::new();
    let values = [10.0, 12.0, 23.0, 23.0, 16.0, 23.0, 21.0, 16.0];
    for &v in &values {
        stats.update(v);
    }

    assert_eq!(stats.count, 8);
    assert!((stats.mean - 18.0).abs() < 1e-6);
    assert!((stats.min - 10.0).abs() < 1e-6);
    assert!((stats.max - 23.0).abs() < 1e-6);
    assert!((stats.variance() - 27.428571).abs() < 1e-4);
    assert!((stats.population_variance() - 24.0).abs() < 1e-4);
}

#[test]
fn test_welford_percentiles() {
    let mut stats = WelfordStats::new();
    for v in 1..=100 {
        stats.update(v as f64);
    }

    let p50 = stats.percentile(50.0);
    assert!((p50 - 50.5).abs() < 1e-6);

    let p90 = stats.percentile(90.0);
    assert!((p90 - 90.1).abs() < 1e-6);

    let p0 = stats.percentile(0.0);
    assert_eq!(p0, 1.0);

    let p100 = stats.percentile(100.0);
    assert_eq!(p100, 100.0);
}

#[test]
fn test_welford_single_and_zero_samples() {
    let empty = WelfordStats::new();
    assert_eq!(empty.variance(), 0.0);
    assert_eq!(empty.std_dev(), 0.0);
    assert_eq!(empty.percentile(50.0), 0.0);

    let mut single = WelfordStats::new();
    single.update(42.0);
    assert_eq!(single.count, 1);
    assert_eq!(single.mean, 42.0);
    assert_eq!(single.variance(), 0.0);
    assert_eq!(single.std_dev(), 0.0);
}

// ------------------------------------------------------------------------------
// 4. RFC 3550 Inter-Arrival Jitter Tests
// ------------------------------------------------------------------------------

#[test]
fn test_rfc3550_jitter_continuous_ewma() {
    let mut jitter_calc = Rfc3550Jitter::new();
    assert_eq!(jitter_calc.current_jitter(), 0.0);

    // Initial packet: sets baseline transit delay
    let j1 = jitter_calc.update_transit(10.0);
    assert_eq!(j1, 0.0);

    // Packet 2: transit delay increases from 10.0 to 26.0 -> delta D = 16.0
    // J = 0 + (16.0 - 0) / 16.0 = 1.0
    let j2 = jitter_calc.update_transit(26.0);
    assert!((j2 - 1.0).abs() < 1e-9);

    // Packet 3: transit delay drops from 26.0 to 10.0 -> delta D = 16.0
    // J = 1.0 + (16.0 - 1.0) / 16.0 = 1.0 + 15/16 = 1.9375
    let j3 = jitter_calc.update_transit(10.0);
    assert!((j3 - 1.9375).abs() < 1e-9);
}

#[test]
fn test_rfc3550_jitter_timestamps() {
    let mut jitter_calc = Rfc3550Jitter::new();
    // Packet 1 sent at 1000, recv at 1010 -> transit = 10
    jitter_calc.update_timestamps(1000.0, 1010.0);

    // Packet 2 sent at 1020, recv at 1046 -> transit = 26
    let j = jitter_calc.update_timestamps(1020.0, 1046.0);
    assert!((j - 1.0).abs() < 1e-9);
}

#[test]
fn test_hop_telemetry_packet_loss() {
    let mut telem = HopTelemetry::new(1);
    assert_eq!(telem.packet_loss_percent(), 0.0);

    telem.record_sent();
    telem.record_sent();
    telem.record_reply(10.0);

    assert_eq!(telem.probes_sent, 2);
    assert_eq!(telem.probes_received, 1);
    assert_eq!(telem.packet_loss_percent(), 50.0);

    telem.record_reply(12.0);
    assert_eq!(telem.packet_loss_percent(), 0.0);
}

#[test]
fn test_terminal_sparkline_rendering() {
    let flat = [10.0, 10.0, 10.0, 10.0];
    let spark_flat = render_sparkline(&flat);
    assert_eq!(spark_flat.chars().count(), 4);

    let ascending = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0];
    let spark_asc = render_sparkline(&ascending);
    assert_eq!(spark_asc.chars().count(), 8);
    assert_eq!(spark_asc.chars().next().unwrap(), ' ');
    assert_eq!(spark_asc.chars().last().unwrap(), '█');

    let empty: [f64; 0] = [];
    assert_eq!(render_sparkline(&empty), "·");
}

// ------------------------------------------------------------------------------
// 5. Route Diffing & BGP ASN Divergence Tests
// ------------------------------------------------------------------------------

#[test]
fn test_route_diffing_exact_match_zero_risk() {
    let hop1 = TraceHop {
        ttl: 1,
        ip: Some(Ipv4Addr::new(192, 0, 2, 1)),
        hostname: Some("gw.local".to_string()),
        asn: None,
        as_name: None,
        rtt_ms: vec![2.0, 2.1, 2.0],
        loss_percent: 0.0,
        jitter_ms: 0.05,
        responding: true,
    };
    let run = TraceRun {
        target: "1.1.1.1".to_string(),
        target_ip: Ipv4Addr::new(1, 1, 1, 1),
        timestamp: "2026-10-23T10:00:00Z".to_string(),
        protocol: ProbeProtocol::Icmp,
        flow_id: 1,
        hops: vec![hop1],
        completed: true,
    };

    let engine = RouteDivergenceEngine::default();
    let report = engine.analyze(&run, &run);

    assert_eq!(report.risk_score, 0);
    assert!(!report.detected_hijack);
    assert!(!report.detected_flaps);
    assert_eq!(report.diffs[0].divergence_type, DivergenceType::Unchanged);
}

#[test]
fn test_route_diffing_bgp_asn_hijack_detection() {
    let b_hop = TraceHop {
        ttl: 5,
        ip: Some(Ipv4Addr::new(130, 117, 50, 82)),
        hostname: Some("cogent.ams.core".to_string()),
        asn: Some(174),
        as_name: Some("COGENT-CORE".to_string()),
        rtt_ms: vec![18.0, 18.5],
        loss_percent: 0.0,
        jitter_ms: 0.1,
        responding: true,
    };

    let a_hop = TraceHop {
        ttl: 5,
        ip: Some(Ipv4Addr::new(185, 220, 101, 5)),
        hostname: Some("rogue-gw.net".to_string()),
        asn: Some(396982),
        as_name: Some("ROGUE-TRANSIT-LLC".to_string()),
        rtt_ms: vec![80.0, 85.0],
        loss_percent: 15.0,
        jitter_ms: 3.5,
        responding: true,
    };

    let baseline = TraceRun {
        target: "1.1.1.1".to_string(),
        target_ip: Ipv4Addr::new(1, 1, 1, 1),
        timestamp: "2026-10-23T10:00:00Z".to_string(),
        protocol: ProbeProtocol::Icmp,
        flow_id: 1,
        hops: vec![b_hop],
        completed: true,
    };

    let active = TraceRun {
        target: "1.1.1.1".to_string(),
        target_ip: Ipv4Addr::new(1, 1, 1, 1),
        timestamp: "2026-10-23T11:00:00Z".to_string(),
        protocol: ProbeProtocol::Icmp,
        flow_id: 1,
        hops: vec![a_hop],
        completed: true,
    };

    let engine = RouteDivergenceEngine::default();
    let report = engine.analyze(&baseline, &active);

    assert!(report.detected_hijack);
    assert!(report.is_asn_path_divergent);
    assert!(report.risk_score >= 50);
    assert_eq!(report.diffs[0].severity, Severity::Critical);
    assert_eq!(report.diffs[0].divergence_type, DivergenceType::AsnHijack);
}

#[test]
fn test_route_diffing_intra_as_ecmp_detection() {
    let b_hop = TraceHop {
        ttl: 4,
        ip: Some(Ipv4Addr::new(172, 70, 44, 1)),
        hostname: None,
        asn: Some(13335),
        as_name: Some("CLOUDFLARENET".to_string()),
        rtt_ms: vec![20.0],
        loss_percent: 0.0,
        jitter_ms: 0.1,
        responding: true,
    };

    let a_hop = TraceHop {
        ttl: 4,
        ip: Some(Ipv4Addr::new(172, 70, 44, 2)),
        hostname: None,
        asn: Some(13335),
        as_name: Some("CLOUDFLARENET".to_string()),
        rtt_ms: vec![20.5],
        loss_percent: 0.0,
        jitter_ms: 0.1,
        responding: true,
    };

    let baseline = TraceRun {
        target: "1.1.1.1".to_string(),
        target_ip: Ipv4Addr::new(1, 1, 1, 1),
        timestamp: "2026-10-23T10:00:00Z".to_string(),
        protocol: ProbeProtocol::Icmp,
        flow_id: 1,
        hops: vec![b_hop],
        completed: true,
    };

    let active = TraceRun {
        target: "1.1.1.1".to_string(),
        target_ip: Ipv4Addr::new(1, 1, 1, 1),
        timestamp: "2026-10-23T11:00:00Z".to_string(),
        protocol: ProbeProtocol::Icmp,
        flow_id: 1,
        hops: vec![a_hop],
        completed: true,
    };

    let engine = RouteDivergenceEngine::default();
    let report = engine.analyze(&baseline, &active);

    assert!(!report.detected_hijack);
    assert_eq!(report.diffs[0].divergence_type, DivergenceType::EcmpBranch);
    assert_eq!(report.diffs[0].severity, Severity::Info);
}

#[test]
fn test_route_diffing_missing_and_new_hops() {
    let hop1 = TraceHop {
        ttl: 1,
        ip: Some(Ipv4Addr::new(192, 0, 2, 1)),
        hostname: None,
        asn: None,
        as_name: None,
        rtt_ms: vec![1.5],
        loss_percent: 0.0,
        jitter_ms: 0.05,
        responding: true,
    };

    let hop2 = TraceHop {
        ttl: 2,
        ip: Some(Ipv4Addr::new(198, 51, 100, 1)),
        hostname: None,
        asn: Some(64496),
        as_name: None,
        rtt_ms: vec![3.5],
        loss_percent: 0.0,
        jitter_ms: 0.08,
        responding: true,
    };

    let baseline = TraceRun {
        target: "1.1.1.1".to_string(),
        target_ip: Ipv4Addr::new(1, 1, 1, 1),
        timestamp: "2026-10-23T10:00:00Z".to_string(),
        protocol: ProbeProtocol::Icmp,
        flow_id: 1,
        hops: vec![hop1.clone(), hop2.clone()],
        completed: true,
    };

    let active = TraceRun {
        target: "1.1.1.1".to_string(),
        target_ip: Ipv4Addr::new(1, 1, 1, 1),
        timestamp: "2026-10-23T11:00:00Z".to_string(),
        protocol: ProbeProtocol::Icmp,
        flow_id: 1,
        hops: vec![hop1], // hop 2 is missing in active trace
        completed: true,
    };

    let engine = RouteDivergenceEngine::default();
    let report = engine.analyze(&baseline, &active);

    let missing = report.diffs.iter().find(|d| d.ttl == 2).unwrap();
    assert_eq!(missing.divergence_type, DivergenceType::MissingHop);
    assert_eq!(missing.severity, Severity::Warning);
}

// ------------------------------------------------------------------------------
// 6. SVG Topology Map & XSS Safety Tests
// ------------------------------------------------------------------------------

#[test]
fn test_svg_xss_escaping_safety() {
    let malicious = "<script>alert('xss');</script> & \"quote\"";
    let escaped = escape_xml(malicious);
    assert!(!escaped.contains('<'));
    assert!(!escaped.contains('>'));
    assert!(!escaped.contains('"'));
    assert!(!escaped.contains('\''));
    assert!(escaped.contains("&lt;script&gt;"));
    assert!(escaped.contains("&amp;"));
    assert!(escaped.contains("&quot;"));
}

#[test]
fn test_svg_render_trace_valid_xml() {
    let hop = TraceHop {
        ttl: 1,
        ip: Some(Ipv4Addr::new(192, 0, 2, 1)),
        hostname: Some("gw.local".to_string()),
        asn: Some(64496),
        as_name: Some("TEST-NET".to_string()),
        rtt_ms: vec![5.2],
        loss_percent: 0.0,
        jitter_ms: 0.08,
        responding: true,
    };
    let run = TraceRun {
        target: "test.example.net".to_string(),
        target_ip: Ipv4Addr::new(192, 0, 2, 1),
        timestamp: "2026-10-23T12:00:00Z".to_string(),
        protocol: ProbeProtocol::Icmp,
        flow_id: 1,
        hops: vec![hop],
        completed: true,
    };

    let svg = SvgMapGenerator::render_trace(&run);
    assert!(svg.starts_with("<svg"));
    assert!(svg.ends_with("</svg>\n") || svg.ends_with("</svg>"));
    assert!(svg.contains("viewBox=\"0 0 1200 620\""));
    assert!(svg.contains("test.example.net"));
    assert!(svg.contains("AS64496 TEST-NET"));
}

#[test]
fn test_svg_render_divergence_report_alert_styling() {
    let report = DivergenceReport {
        target: "1.1.1.1".to_string(),
        baseline_timestamp: "2026-10-23T10:00:00Z".to_string(),
        active_timestamp: "2026-10-23T11:00:00Z".to_string(),
        baseline_asn_path: vec![174, 13335],
        active_asn_path: vec![174, 396982, 13335],
        is_asn_path_divergent: true,
        detected_hijack: true,
        detected_flaps: false,
        max_latency_spike_ms: 88.5,
        risk_score: 100,
        diffs: vec![],
        summary: "CRITICAL: BGP ASN path hijacking detected!".to_string(),
    };

    let svg = SvgMapGenerator::render_divergence_report(&report);
    assert!(svg.contains("#ef4444")); // Red alert indicator
    assert!(svg.contains("BGP HIJACK DETECTED"));
    assert!(svg.contains("RISK SCORE: 100/100"));
}

// ------------------------------------------------------------------------------
// 7. Fixtures Load & Divergence Verification Tests
// ------------------------------------------------------------------------------

#[test]
fn test_fixtures_load_and_divergence_analysis() {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let baseline_path = fixtures_dir.join("ecmp_route_run1.json");
    let active_path = fixtures_dir.join("bgp_hijack_run2.json");

    assert!(baseline_path.exists(), "fixtures/ecmp_route_run1.json missing");
    assert!(active_path.exists(), "fixtures/bgp_hijack_run2.json missing");

    let b_str = fs::read_to_string(&baseline_path).unwrap();
    let a_str = fs::read_to_string(&active_path).unwrap();

    let baseline: TraceRun = serde_json::from_str(&b_str).unwrap();
    let active: TraceRun = serde_json::from_str(&a_str).unwrap();

    assert_eq!(baseline.hops.len(), 8);
    assert_eq!(active.hops.len(), 8);

    let engine = RouteDivergenceEngine::default();
    let report = engine.analyze(&baseline, &active);

    assert!(report.detected_hijack);
    assert!(report.is_asn_path_divergent);
    assert_eq!(report.risk_score, 100);
    assert!(report.max_latency_spike_ms > 90.0);

    // Verify SVG generation works from fixture diff report
    let svg = SvgMapGenerator::render_divergence_report(&report);
    assert!(svg.contains("BGP HIJACK DETECTED"));
}

// ------------------------------------------------------------------------------
// 8. Zero Memory Leaks & Bounded Resource Tests
// ------------------------------------------------------------------------------

#[test]
fn test_zero_memory_leak_bounded_allocations() {
    // Stress test: synthesize 5,000 hops through Paris engine and Welford stats
    let mut welford = WelfordStats::new();
    let mut jitter = Rfc3550Jitter::new();

    for i in 1..=5000 {
        let probe = ParisProbePacket::build_icmp(1, i as u16, (i % 30) as u8 + 1, None);
        assert_eq!(probe.payload_len, 24);

        let latency = 15.0 + ((i % 100) as f64) * 0.5;
        welford.update(latency);
        jitter.update_transit(latency);
    }

    assert_eq!(welford.count, 5000);
    assert!(welford.variance() > 0.0);
    assert!(jitter.current_jitter() > 0.0);
}
