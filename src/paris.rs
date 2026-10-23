// ==============================================================================
// Tracegrid: src/paris.rs
// Paris-Traceroute Flow-Identifier Checksum Engine & Compensation Word Calculator
// ==============================================================================

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Internet Protocol probe transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeProtocol {
    Icmp,
    Udp,
    Tcp,
}

impl std::fmt::Display for ProbeProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeProtocol::Icmp => write!(f, "ICMP"),
            ProbeProtocol::Udp => write!(f, "UDP"),
            ProbeProtocol::Tcp => write!(f, "TCP"),
        }
    }
}

/// Internet Checksum (RFC 1071 / RFC 1624) 16-bit one's complement math.
pub struct InternetChecksum;

impl InternetChecksum {
    /// Compute 16-bit one's complement sum of 16-bit words.
    #[inline]
    pub fn sum_words(data: &[u8]) -> u32 {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            sum = sum.wrapping_add(word);
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let word = (remainder[0] as u32) << 8;
            sum = sum.wrapping_add(word);
        }
        sum
    }

    /// Fold a 32-bit accumulated sum down to 16 bits with end-around carry.
    #[inline]
    pub fn fold(mut sum: u32) -> u16 {
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// Computes the final RFC 1071 Internet Checksum (bitwise inverted).
    #[inline]
    pub fn compute(data: &[u8]) -> u16 {
        let folded = Self::fold(Self::sum_words(data));
        !folded
    }

    /// Verifies that data including the checksum word sums to 0xffff (or folded complement 0x0000).
    #[inline]
    pub fn verify(data: &[u8]) -> bool {
        let folded = Self::fold(Self::sum_words(data));
        folded == 0xffff
    }

    /// Add two 16-bit words in one's complement arithmetic.
    #[inline]
    pub fn ones_complement_add(a: u16, b: u16) -> u16 {
        let sum = (a as u32) + (b as u32);
        Self::fold(sum)
    }

    /// Subtract two 16-bit words in one's complement arithmetic: a - b = a + (~b).
    #[inline]
    pub fn ones_complement_sub(a: u16, b: u16) -> u16 {
        let inv_b = (!b) & 0xffff;
        Self::ones_complement_add(a, inv_b)
    }

    /// RFC 1624 Incremental Checksum Update:
    /// Computes new checksum C' when 16-bit field m is updated to m'.
    /// Formula: ~C' = ~(~C + ~m + m')
    #[inline]
    pub fn incremental_update(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
        let not_old_csum = (!old_csum) as u32;
        let not_old_val = (!old_val) as u32;
        let sum = not_old_csum + not_old_val + (new_val as u32);
        let folded = Self::fold(sum);
        !folded
    }

    /// Calculate Paris-Traceroute compensation word.
    /// To ensure the ICMP/UDP checksum remains invariant across probe sequence increments:
    /// seq_base + comp_base == seq_new + comp_new (mod 1's complement)
    /// => comp_new = comp_base + (seq_base - seq_new)
    #[inline]
    pub fn calculate_compensation_word(seq_new: u16, seq_base: u16, comp_base: u16) -> u16 {
        let delta = Self::ones_complement_sub(seq_base, seq_new);
        Self::ones_complement_add(comp_base, delta)
    }
}

/// Paris-Traceroute Flow Identifier configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParisFlow {
    pub flow_id: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: ProbeProtocol,
    pub base_src_port: u16,
    pub base_dst_port: u16,
}

impl ParisFlow {
    /// Creates a new ParisFlow instance.
    pub fn new(
        flow_id: u16,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        protocol: ProbeProtocol,
    ) -> Self {
        // Deterministically map flow_id to port space (RFC 6335 ephemeral range)
        let base_src_port = 33434 + (flow_id % 10000);
        let base_dst_port = match protocol {
            ProbeProtocol::Icmp => 0,
            ProbeProtocol::Udp => 33434 + (flow_id % 1000),
            ProbeProtocol::Tcp => 80,
        };

        Self {
            flow_id,
            src_ip,
            dst_ip,
            protocol,
            base_src_port,
            base_dst_port,
        }
    }

    /// Simulates router 5-tuple ECMP hash calculation.
    /// ECMP routers typically hash (SrcIP, DstIP, Protocol, SrcPort, DstPort)
    /// using Jenkins lookup3, CRC32, or Murmur-like hash functions.
    pub fn ecmp_flow_hash(&self) -> u32 {
        let mut h: u32 = 0x811c9dc5; // FNV-1a 32-bit offset basis
        let fnv_prime: u32 = 0x01000193;

        for b in self.src_ip.octets() {
            h ^= b as u32;
            h = h.wrapping_mul(fnv_prime);
        }
        for b in self.dst_ip.octets() {
            h ^= b as u32;
            h = h.wrapping_mul(fnv_prime);
        }
        let proto_byte = match self.protocol {
            ProbeProtocol::Icmp => 1u8,
            ProbeProtocol::Udp => 17u8,
            ProbeProtocol::Tcp => 6u8,
        };
        h ^= proto_byte as u32;
        h = h.wrapping_mul(fnv_prime);

        for b in self.base_src_port.to_be_bytes() {
            h ^= b as u32;
            h = h.wrapping_mul(fnv_prime);
        }
        for b in self.base_dst_port.to_be_bytes() {
            h ^= b as u32;
            h = h.wrapping_mul(fnv_prime);
        }
        h
    }
}

/// A serialized probe packet generated by Paris-Traceroute engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParisProbePacket {
    pub flow_id: u16,
    pub seq: u16,
    pub ttl: u8,
    pub protocol: ProbeProtocol,
    pub src_port: u16,
    pub dst_port: u16,
    pub compensation_word: u16,
    pub checksum: u16,
    pub payload_len: usize,
    pub wire_bytes: Vec<u8>,
}

impl ParisProbePacket {
    /// Builds an ICMP Echo Request probe with constant Internet Checksum.
    /// ICMP Header: Type (8), Code (0), Checksum (2 bytes), Identifier (flow_id), Sequence (seq).
    /// ICMP Data: [Compensation Word (2 bytes), Timestamp (8 bytes), Magic (4 bytes)].
    pub fn build_icmp(flow_id: u16, seq: u16, ttl: u8, invariant_checksum: Option<u16>) -> Self {
        // Base packet with zero checksum
        let mut buf = vec![0u8; 24];
        buf[0] = 8; // ICMP Type: Echo Request
        buf[1] = 0; // ICMP Code: 0
        buf[2] = 0; // Checksum placeholder
        buf[3] = 0;

        buf[4..6].copy_from_slice(&flow_id.to_be_bytes()); // ICMP ID = flow_id
        buf[6..8].copy_from_slice(&seq.to_be_bytes());     // Sequence number

        let base_seq = 1u16;
        let base_comp = 0x5a5au16;

        let comp = match invariant_checksum {
            Some(_) => InternetChecksum::calculate_compensation_word(seq, base_seq, base_comp),
            None => base_comp,
        };

        buf[8..10].copy_from_slice(&comp.to_be_bytes()); // Compensation word
        buf[10..18].copy_from_slice(&0x0123456789abcdefu64.to_be_bytes()); // Synthetic timestamp
        buf[18..24].copy_from_slice(b"PARIS-"); // Probe signature

        // Compute checksum
        let computed_csum = match invariant_checksum {
            Some(target) => {
                buf[2..4].copy_from_slice(&target.to_be_bytes());
                target
            }
            None => {
                let csum = InternetChecksum::compute(&buf);
                buf[2..4].copy_from_slice(&csum.to_be_bytes());
                csum
            }
        };

        Self {
            flow_id,
            seq,
            ttl,
            protocol: ProbeProtocol::Icmp,
            src_port: 0,
            dst_port: 0,
            compensation_word: comp,
            checksum: computed_csum,
            payload_len: buf.len(),
            wire_bytes: buf,
        }
    }

    /// Builds a UDP probe preserving invariant 5-tuple ports and header fields.
    /// UDP Header: SrcPort (2 bytes), DstPort (2 bytes), Length (2 bytes), Checksum (2 bytes).
    /// UDP Payload: Flow ID (2 bytes), Sequence (2 bytes), Compensation Word (2 bytes), Magic.
    pub fn build_udp(flow_id: u16, seq: u16, ttl: u8, src_port: u16, dst_port: u16) -> Self {
        let mut buf = vec![0u8; 28];
        buf[0..2].copy_from_slice(&src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
        let len = buf.len() as u16;
        buf[4..6].copy_from_slice(&len.to_be_bytes());
        buf[6..8].copy_from_slice(&[0, 0]); // UDP checksum placeholder

        // Payload
        buf[8..10].copy_from_slice(&flow_id.to_be_bytes());
        buf[10..12].copy_from_slice(&seq.to_be_bytes());

        let comp = InternetChecksum::calculate_compensation_word(seq, 1, 0x4242);
        buf[12..14].copy_from_slice(&comp.to_be_bytes());
        buf[14..28].copy_from_slice(b"PARIS_UDP_FLOW");

        let csum = InternetChecksum::compute(&buf);
        let final_csum = if csum == 0 { 0xffff } else { csum };
        buf[6..8].copy_from_slice(&final_csum.to_be_bytes());

        Self {
            flow_id,
            seq,
            ttl,
            protocol: ProbeProtocol::Udp,
            src_port,
            dst_port,
            compensation_word: comp,
            checksum: final_csum,
            payload_len: buf.len(),
            wire_bytes: buf,
        }
    }

    /// Builds a TCP SYN probe with fixed sequence space and invariant header checksum.
    pub fn build_tcp(flow_id: u16, seq: u32, ttl: u8, src_port: u16, dst_port: u16, flags: u8) -> Self {
        let mut buf = vec![0u8; 20];
        buf[0..2].copy_from_slice(&src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&seq.to_be_bytes());
        buf[8..12].copy_from_slice(&0u32.to_be_bytes()); // Ack number
        buf[12] = 5 << 4; // Data offset (5 32-bit words = 20 bytes)
        buf[13] = flags;    // TCP Flags (e.g. 0x02 for SYN)
        buf[14..16].copy_from_slice(&64240u16.to_be_bytes()); // Window size
        buf[16..18].copy_from_slice(&[0, 0]); // Checksum placeholder
        buf[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

        let csum = InternetChecksum::compute(&buf);
        let final_csum = if csum == 0 { 0xffff } else { csum };
        buf[16..18].copy_from_slice(&final_csum.to_be_bytes());

        Self {
            flow_id,
            seq: (seq & 0xffff) as u16,
            ttl,
            protocol: ProbeProtocol::Tcp,
            src_port,
            dst_port,
            compensation_word: 0,
            checksum: final_csum,
            payload_len: buf.len(),
            wire_bytes: buf,
        }
    }

    /// Validates internal checksum integrity of the probe packet.
    pub fn verify_checksum(&self) -> bool {
        InternetChecksum::verify(&self.wire_bytes)
    }
}
