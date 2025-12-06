use std::net::{Ipv4Addr, Ipv6Addr};

use crate::checksum;
use crate::config::{self, ParsedConfig};

// IP protocol numbers
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_FRAGMENT: u8 = 44;

// IPv4 header size (no options)
const IPV4_HEADER_LEN: usize = 20;
// IPv6 header size
const IPV6_HEADER_LEN: usize = 40;
// IPv6 fragment header size
const IPV6_FRAG_HEADER_LEN: usize = 8;
// MTU overhead difference between IPv6 and IPv4 headers
const MTU_ADJ: u16 = (IPV6_HEADER_LEN - IPV4_HEADER_LEN) as u16;

// ICMP types (v4)
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_DEST_UNREACHABLE: u8 = 3;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;

// ICMPv4 unreachable codes
const ICMP_UNREACH_NET: u8 = 0;
const ICMP_UNREACH_HOST: u8 = 1;
const ICMP_UNREACH_PROTOCOL: u8 = 2;
const ICMP_UNREACH_PORT: u8 = 3;
const ICMP_UNREACH_NEEDFRAG: u8 = 4;

// ICMPv6 types
const ICMPV6_DEST_UNREACHABLE: u8 = 1;
const ICMPV6_PACKET_TOO_BIG: u8 = 2;
const ICMPV6_TIME_EXCEEDED: u8 = 3;
const ICMPV6_PARAM_PROBLEM: u8 = 4;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

// ICMPv6 unreachable codes
const ICMPV6_UNREACH_NOROUTE: u8 = 0;
const ICMPV6_UNREACH_ADMIN: u8 = 1;
const ICMPV6_UNREACH_ADDR: u8 = 3;
const ICMPV6_UNREACH_PORT: u8 = 4;

/// Errors that can occur during translation
#[derive(Debug)]
pub enum TranslateError {
    PacketTooShort,
    InvalidHeader,
    AddressNotMapped,
    IcmpTranslationUnsupported,
}

/// Result of a successful translation — a fully-formed packet to write to the TUN device.
pub struct TranslatedPacket {
    pub data: Vec<u8>,
}

/// Map an IPv4 address to IPv6 using config (static maps first, then prefix embedding).
fn map_ip4_to_ip6(config: &ParsedConfig, addr: &Ipv4Addr) -> Option<Ipv6Addr> {
    // Check static mappings first
    if let Some(v6) = config.map4to6.get(addr) {
        return Some(*v6);
    }
    // Fall back to prefix embedding
    Some(config::embed_ipv4_in_prefix(&config.prefix, addr))
}

/// Map an IPv6 address to IPv4 using config (static maps first, then prefix extraction).
fn map_ip6_to_ip4(config: &ParsedConfig, addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    // Check static mappings first
    if let Some(v4) = config.map6to4.get(addr) {
        return Some(*v4);
    }
    // Fall back to prefix extraction
    config::extract_ipv4_from_prefix(&config.prefix, addr)
}

/// Translate an IPv4 packet to IPv6.
pub fn translate_4to6(
    config: &ParsedConfig,
    packet: &[u8],
) -> Result<TranslatedPacket, TranslateError> {
    if packet.len() < IPV4_HEADER_LEN {
        return Err(TranslateError::PacketTooShort);
    }

    let version_ihl = packet[0];
    if (version_ihl >> 4) != 4 {
        return Err(TranslateError::InvalidHeader);
    }
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < IPV4_HEADER_LEN || packet.len() < ihl {
        return Err(TranslateError::InvalidHeader);
    }

    let tos = packet[1];
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || packet.len() < total_len {
        return Err(TranslateError::InvalidHeader);
    }

    let identification = u16::from_be_bytes([packet[4], packet[5]]);
    let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
    let _dont_fragment = (flags_frag & 0x4000) != 0;
    let more_fragments = (flags_frag & 0x2000) != 0;
    let frag_offset = flags_frag & 0x1fff;

    let ttl = packet[8];
    if ttl <= 1 {
        // Would need to generate ICMP time exceeded — drop for now
        log::debug!("Dropping IPv4 packet: TTL expired");
        return Err(TranslateError::InvalidHeader);
    }

    let protocol = packet[9];
    let src4 = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst4 = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    // Map addresses
    let src6 = map_ip4_to_ip6(config, &src4).ok_or(TranslateError::AddressNotMapped)?;
    let dst6 = map_ip4_to_ip6(config, &dst4).ok_or(TranslateError::AddressNotMapped)?;

    let payload = &packet[ihl..total_len];

    // Translate protocol number and payload
    let (next_header, translated_payload) =
        translate_payload_4to6(protocol, payload, &src4, &dst4, &src6, &dst6)?;

    // Decide whether we need a fragment header
    let is_fragment = more_fragments || frag_offset != 0;
    // Only add IPv6 fragment header if the IPv4 packet was actually fragmented
    let need_frag_header = is_fragment;

    let payload_len = if need_frag_header {
        IPV6_FRAG_HEADER_LEN + translated_payload.len()
    } else {
        translated_payload.len()
    };

    // Build IPv6 header
    let mut out = Vec::with_capacity(IPV6_HEADER_LEN + payload_len);

    // Version (6), traffic class, flow label
    let ver_tc_fl: u32 = (6 << 28) | ((tos as u32) << 20);
    out.extend_from_slice(&ver_tc_fl.to_be_bytes());

    // Payload length
    out.extend_from_slice(&(payload_len as u16).to_be_bytes());

    // Next header
    if need_frag_header {
        out.push(IPPROTO_FRAGMENT);
    } else {
        out.push(next_header);
    }

    // Hop limit (decremented TTL)
    out.push(ttl - 1);

    // Source and destination IPv6 addresses
    out.extend_from_slice(&src6.octets());
    out.extend_from_slice(&dst6.octets());

    // Fragment header if needed
    if need_frag_header {
        out.push(next_header); // Next header in frag header
        out.push(0); // Reserved
        let frag_off_mf = (frag_offset << 3) | if more_fragments { 1 } else { 0 };
        out.extend_from_slice(&frag_off_mf.to_be_bytes());
        out.extend_from_slice(&(identification as u32).to_be_bytes());
    }

    out.extend_from_slice(&translated_payload);

    Ok(TranslatedPacket { data: out })
}

/// Translate an IPv6 packet to IPv4.
pub fn translate_6to4(
    config: &ParsedConfig,
    packet: &[u8],
) -> Result<TranslatedPacket, TranslateError> {
    if packet.len() < IPV6_HEADER_LEN {
        return Err(TranslateError::PacketTooShort);
    }

    let version = packet[0] >> 4;
    if version != 6 {
        return Err(TranslateError::InvalidHeader);
    }

    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let mut next_header = packet[6];
    let hop_limit = packet[7];

    if hop_limit <= 1 {
        log::debug!("Dropping IPv6 packet: hop limit expired");
        return Err(TranslateError::InvalidHeader);
    }

    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());

    // Map addresses
    let src4 = map_ip6_to_ip4(config, &src6).ok_or(TranslateError::AddressNotMapped)?;
    let dst4 = map_ip6_to_ip4(config, &dst6).ok_or(TranslateError::AddressNotMapped)?;

    // Walk extension headers to find the payload
    let mut offset = IPV6_HEADER_LEN;
    let packet_end = IPV6_HEADER_LEN + payload_len;
    if packet.len() < packet_end {
        return Err(TranslateError::PacketTooShort);
    }

    let mut frag_offset: u16 = 0;
    let mut more_fragments = false;
    let mut identification: u32 = 0;
    let mut has_frag_header = false;

    // Process extension headers
    loop {
        match next_header {
            IPPROTO_FRAGMENT => {
                if offset + IPV6_FRAG_HEADER_LEN > packet_end {
                    return Err(TranslateError::PacketTooShort);
                }
                has_frag_header = true;
                next_header = packet[offset]; // Next Header in frag header
                let frag_off_mf = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                frag_offset = frag_off_mf >> 3;
                more_fragments = (frag_off_mf & 1) != 0;
                identification = u32::from_be_bytes([
                    packet[offset + 4],
                    packet[offset + 5],
                    packet[offset + 6],
                    packet[offset + 7],
                ]);
                offset += IPV6_FRAG_HEADER_LEN;
            }
            // Hop-by-hop, destination options, routing — skip them
            0 | 43 | 60 => {
                if offset + 2 > packet_end {
                    return Err(TranslateError::PacketTooShort);
                }
                next_header = packet[offset];
                let ext_len = (packet[offset + 1] as usize + 1) * 8;
                offset += ext_len;
            }
            _ => break,
        }
    }

    let payload = &packet[offset..packet_end];

    // Translate protocol and payload
    let (ipv4_proto, translated_payload) =
        translate_payload_6to4(next_header, payload, &src6, &dst6, &src4, &dst4)?;

    // Build IPv4 packet
    let total_len = (IPV4_HEADER_LEN + translated_payload.len()) as u16;
    let mut out = Vec::with_capacity(total_len as usize);

    // Version + IHL (5 = 20 bytes, no options)
    out.push(0x45);
    // TOS = traffic class
    out.push(traffic_class);
    // Total length
    out.extend_from_slice(&total_len.to_be_bytes());

    // Identification
    if has_frag_header {
        out.extend_from_slice(&(identification as u16).to_be_bytes());
    } else {
        out.extend_from_slice(&0u16.to_be_bytes());
    }

    // Flags + Fragment offset
    let flags_frag = if has_frag_header {
        (frag_offset & 0x1fff) | if more_fragments { 0x2000 } else { 0 }
    } else {
        // Set DF for unfragmented packets
        0x4000
    };
    out.extend_from_slice(&flags_frag.to_be_bytes());

    // TTL (decremented hop limit)
    out.push(hop_limit - 1);
    // Protocol
    out.push(ipv4_proto);
    // Header checksum placeholder
    out.extend_from_slice(&0u16.to_be_bytes());
    // Source and destination IPv4
    out.extend_from_slice(&src4.octets());
    out.extend_from_slice(&dst4.octets());

    // Calculate and fill in header checksum
    let cksum = checksum::ipv4_header_checksum(&out[..IPV4_HEADER_LEN]);
    out[10] = (cksum >> 8) as u8;
    out[11] = (cksum & 0xff) as u8;

    // Append payload
    out.extend_from_slice(&translated_payload);

    Ok(TranslatedPacket { data: out })
}

/// Translate the payload when going from IPv4 to IPv6.
/// Returns (next_header, translated_payload).
fn translate_payload_4to6(
    protocol: u8,
    payload: &[u8],
    src4: &Ipv4Addr,
    dst4: &Ipv4Addr,
    src6: &Ipv6Addr,
    dst6: &Ipv6Addr,
) -> Result<(u8, Vec<u8>), TranslateError> {
    match protocol {
        IPPROTO_ICMP => translate_icmp_4to6(payload, src4, dst4, src6, dst6),
        IPPROTO_TCP => {
            let mut data = payload.to_vec();
            if data.len() >= 18 {
                // TCP checksum at offset 16-17
                let old_cksum = u16::from_be_bytes([data[16], data[17]]);
                let new_cksum = checksum::convert_checksum_4to6(old_cksum, src4, dst4, src6, dst6);
                data[16] = (new_cksum >> 8) as u8;
                data[17] = (new_cksum & 0xff) as u8;
            }
            Ok((IPPROTO_TCP, data))
        }
        IPPROTO_UDP => {
            let mut data = payload.to_vec();
            if data.len() >= 8 {
                let old_cksum = u16::from_be_bytes([data[6], data[7]]);
                if old_cksum == 0 {
                    // UDP over IPv6 requires a checksum — compute from scratch
                    data[6] = 0;
                    data[7] = 0;
                    let new_cksum = checksum::ipv6_pseudo_checksum(src6, dst6, IPPROTO_UDP, &data);
                    let new_cksum = if new_cksum == 0 { 0xffff } else { new_cksum };
                    data[6] = (new_cksum >> 8) as u8;
                    data[7] = (new_cksum & 0xff) as u8;
                } else {
                    let new_cksum =
                        checksum::convert_checksum_4to6(old_cksum, src4, dst4, src6, dst6);
                    let new_cksum = if new_cksum == 0 { 0xffff } else { new_cksum };
                    data[6] = (new_cksum >> 8) as u8;
                    data[7] = (new_cksum & 0xff) as u8;
                }
            }
            Ok((IPPROTO_UDP, data))
        }
        _ => {
            // Pass through other protocols unchanged
            log::debug!(
                "Passing through protocol {} without checksum fixup",
                protocol
            );
            Ok((protocol, payload.to_vec()))
        }
    }
}

/// Translate the payload when going from IPv6 to IPv4.
fn translate_payload_6to4(
    next_header: u8,
    payload: &[u8],
    src6: &Ipv6Addr,
    dst6: &Ipv6Addr,
    src4: &Ipv4Addr,
    dst4: &Ipv4Addr,
) -> Result<(u8, Vec<u8>), TranslateError> {
    match next_header {
        IPPROTO_ICMPV6 => translate_icmp_6to4(payload, src6, dst6, src4, dst4),
        IPPROTO_TCP => {
            let mut data = payload.to_vec();
            if data.len() >= 18 {
                let old_cksum = u16::from_be_bytes([data[16], data[17]]);
                let new_cksum = checksum::convert_checksum_6to4(old_cksum, src6, dst6, src4, dst4);
                data[16] = (new_cksum >> 8) as u8;
                data[17] = (new_cksum & 0xff) as u8;
            }
            Ok((IPPROTO_TCP, data))
        }
        IPPROTO_UDP => {
            let mut data = payload.to_vec();
            if data.len() >= 8 {
                let old_cksum = u16::from_be_bytes([data[6], data[7]]);
                let new_cksum = checksum::convert_checksum_6to4(old_cksum, src6, dst6, src4, dst4);
                // In IPv4, UDP checksum of 0 means "no checksum"
                data[6] = (new_cksum >> 8) as u8;
                data[7] = (new_cksum & 0xff) as u8;
            }
            Ok((IPPROTO_UDP, data))
        }
        _ => {
            log::debug!(
                "Passing through next_header {} without checksum fixup",
                next_header
            );
            Ok((next_header, payload.to_vec()))
        }
    }
}

/// Translate ICMPv4 → ICMPv6
fn translate_icmp_4to6(
    payload: &[u8],
    src4: &Ipv4Addr,
    dst4: &Ipv4Addr,
    src6: &Ipv6Addr,
    dst6: &Ipv6Addr,
) -> Result<(u8, Vec<u8>), TranslateError> {
    if payload.len() < 8 {
        return Err(TranslateError::PacketTooShort);
    }

    let icmp_type = payload[0];
    let icmp_code = payload[1];

    match icmp_type {
        ICMP_ECHO_REQUEST => {
            let mut data = payload.to_vec();
            data[0] = ICMPV6_ECHO_REQUEST;
            // Recompute checksum using ICMPv6 pseudo-header
            data[2] = 0;
            data[3] = 0;
            let cksum = checksum::ipv6_pseudo_checksum(src6, dst6, IPPROTO_ICMPV6, &data);
            data[2] = (cksum >> 8) as u8;
            data[3] = (cksum & 0xff) as u8;
            Ok((IPPROTO_ICMPV6, data))
        }
        ICMP_ECHO_REPLY => {
            let mut data = payload.to_vec();
            data[0] = ICMPV6_ECHO_REPLY;
            data[2] = 0;
            data[3] = 0;
            let cksum = checksum::ipv6_pseudo_checksum(src6, dst6, IPPROTO_ICMPV6, &data);
            data[2] = (cksum >> 8) as u8;
            data[3] = (cksum & 0xff) as u8;
            Ok((IPPROTO_ICMPV6, data))
        }
        ICMP_DEST_UNREACHABLE => {
            translate_icmp_error_4to6(icmp_type, icmp_code, payload, src4, dst4, src6, dst6)
        }
        ICMP_TIME_EXCEEDED => {
            translate_icmp_error_4to6(icmp_type, icmp_code, payload, src4, dst4, src6, dst6)
        }
        _ => {
            log::debug!("Unsupported ICMP type {} for translation", icmp_type);
            Err(TranslateError::IcmpTranslationUnsupported)
        }
    }
}

/// Translate ICMPv6 → ICMPv4
fn translate_icmp_6to4(
    payload: &[u8],
    src6: &Ipv6Addr,
    dst6: &Ipv6Addr,
    src4: &Ipv4Addr,
    dst4: &Ipv4Addr,
) -> Result<(u8, Vec<u8>), TranslateError> {
    if payload.len() < 8 {
        return Err(TranslateError::PacketTooShort);
    }

    let icmp_type = payload[0];
    let icmp_code = payload[1];

    match icmp_type {
        ICMPV6_ECHO_REQUEST => {
            let mut data = payload.to_vec();
            data[0] = ICMP_ECHO_REQUEST;
            // ICMPv4 uses simple checksum (no pseudo-header)
            data[2] = 0;
            data[3] = 0;
            let cksum = checksum::ipv4_header_checksum(&data);
            data[2] = (cksum >> 8) as u8;
            data[3] = (cksum & 0xff) as u8;
            Ok((IPPROTO_ICMP, data))
        }
        ICMPV6_ECHO_REPLY => {
            let mut data = payload.to_vec();
            data[0] = ICMP_ECHO_REPLY;
            data[2] = 0;
            data[3] = 0;
            let cksum = checksum::ipv4_header_checksum(&data);
            data[2] = (cksum >> 8) as u8;
            data[3] = (cksum & 0xff) as u8;
            Ok((IPPROTO_ICMP, data))
        }
        ICMPV6_DEST_UNREACHABLE => {
            translate_icmp_error_6to4(icmp_type, icmp_code, payload, src6, dst6, src4, dst4)
        }
        ICMPV6_PACKET_TOO_BIG => {
            translate_icmp_error_6to4(icmp_type, icmp_code, payload, src6, dst6, src4, dst4)
        }
        ICMPV6_TIME_EXCEEDED => {
            translate_icmp_error_6to4(icmp_type, icmp_code, payload, src6, dst6, src4, dst4)
        }
        _ => {
            log::debug!("Unsupported ICMPv6 type {} for translation", icmp_type);
            Err(TranslateError::IcmpTranslationUnsupported)
        }
    }
}

/// Translate an ICMPv4 error message (containing an embedded IPv4 packet) to ICMPv6.
fn translate_icmp_error_4to6(
    icmp_type: u8,
    icmp_code: u8,
    payload: &[u8],
    _src4: &Ipv4Addr,
    _dst4: &Ipv4Addr,
    src6: &Ipv6Addr,
    dst6: &Ipv6Addr,
) -> Result<(u8, Vec<u8>), TranslateError> {
    // Map ICMPv4 type/code → ICMPv6 type/code
    let (new_type, new_code, mtu_adjust) = match (icmp_type, icmp_code) {
        (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_NET) | (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_HOST) => {
            (ICMPV6_DEST_UNREACHABLE, ICMPV6_UNREACH_NOROUTE, false)
        }
        (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_PROTOCOL) => {
            (ICMPV6_PARAM_PROBLEM, 1u8, false) // Unrecognized next header
        }
        (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_PORT) => {
            (ICMPV6_DEST_UNREACHABLE, ICMPV6_UNREACH_PORT, false)
        }
        (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_NEEDFRAG) => (ICMPV6_PACKET_TOO_BIG, 0, true),
        (ICMP_DEST_UNREACHABLE, 9) | (ICMP_DEST_UNREACHABLE, 10) | (ICMP_DEST_UNREACHABLE, 13) => {
            (ICMPV6_DEST_UNREACHABLE, ICMPV6_UNREACH_ADMIN, false)
        }
        (ICMP_TIME_EXCEEDED, _) => (ICMPV6_TIME_EXCEEDED, icmp_code, false),
        _ => (ICMPV6_DEST_UNREACHABLE, ICMPV6_UNREACH_ADDR, false),
    };

    // Build the ICMPv6 error message
    let mut data = Vec::with_capacity(payload.len() + 20);
    data.push(new_type);
    data.push(new_code);
    data.push(0); // checksum placeholder
    data.push(0);

    if mtu_adjust {
        // Packet Too Big: extract MTU from ICMPv4 bytes 6-7 and adjust
        let mtu_v4 = u16::from_be_bytes([payload[6], payload[7]]);
        let mtu_v6 = (mtu_v4 as u32 + MTU_ADJ as u32).min(0xffff);
        data.extend_from_slice(&mtu_v6.to_be_bytes());
    } else {
        // Unused / pointer field
        data.extend_from_slice(&payload[4..8]);
    }

    // Translate the embedded IPv4 packet header to IPv6
    let embedded = &payload[8..];
    if embedded.len() >= IPV4_HEADER_LEN {
        let em_ihl = ((embedded[0] & 0x0f) as usize) * 4;
        if embedded.len() >= em_ihl {
            let em_tos = embedded[1];
            let em_payload_len = (embedded.len() - em_ihl) as u16;
            let em_ttl = embedded[8];
            let mut em_proto = embedded[9];
            let em_src4 = Ipv4Addr::new(embedded[12], embedded[13], embedded[14], embedded[15]);
            let em_dst4 = Ipv4Addr::new(embedded[16], embedded[17], embedded[18], embedded[19]);

            // Map embedded addresses (best effort — use prefix if not statically mapped)
            // Use the outer packet's prefix context for embedding
            // (the first 12 bytes of src6/dst6 carry the /96 prefix)
            let prefix_from_src = {
                let mut p = src6.octets();
                p[12] = 0;
                p[13] = 0;
                p[14] = 0;
                p[15] = 0;
                Ipv6Addr::from(p)
            };
            let prefix_from_dst = {
                let mut p = dst6.octets();
                p[12] = 0;
                p[13] = 0;
                p[14] = 0;
                p[15] = 0;
                Ipv6Addr::from(p)
            };
            let em_src6 = config::embed_ipv4_in_prefix(&prefix_from_src, &em_src4);
            let em_dst6 = config::embed_ipv4_in_prefix(&prefix_from_dst, &em_dst4);

            if em_proto == IPPROTO_ICMP {
                em_proto = IPPROTO_ICMPV6;
            }

            // Build embedded IPv6 header
            let ver_tc_fl: u32 = (6 << 28) | ((em_tos as u32) << 20);
            data.extend_from_slice(&ver_tc_fl.to_be_bytes());
            data.extend_from_slice(&em_payload_len.to_be_bytes());
            data.push(em_proto);
            data.push(em_ttl);
            data.extend_from_slice(&em_src6.octets());
            data.extend_from_slice(&em_dst6.octets());

            // Append as much of the embedded payload as we can (up to 1232 bytes to keep under 1280)
            let remaining = &embedded[em_ihl..];
            let max_embedded = 1280 - IPV6_HEADER_LEN - 8 - IPV6_HEADER_LEN;
            let copy_len = remaining.len().min(max_embedded);
            data.extend_from_slice(&remaining[..copy_len]);
        }
    }

    // Recompute ICMPv6 checksum
    data[2] = 0;
    data[3] = 0;
    let cksum = checksum::ipv6_pseudo_checksum(src6, dst6, IPPROTO_ICMPV6, &data);
    data[2] = (cksum >> 8) as u8;
    data[3] = (cksum & 0xff) as u8;

    Ok((IPPROTO_ICMPV6, data))
}

/// Translate an ICMPv6 error message (containing an embedded IPv6 packet) to ICMPv4.
fn translate_icmp_error_6to4(
    icmp_type: u8,
    icmp_code: u8,
    payload: &[u8],
    _src6: &Ipv6Addr,
    _dst6: &Ipv6Addr,
    _src4: &Ipv4Addr,
    _dst4: &Ipv4Addr,
) -> Result<(u8, Vec<u8>), TranslateError> {
    // Map ICMPv6 type/code → ICMPv4 type/code
    let (new_type, new_code) = match (icmp_type, icmp_code) {
        (ICMPV6_DEST_UNREACHABLE, ICMPV6_UNREACH_NOROUTE) => {
            (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_HOST)
        }
        (ICMPV6_DEST_UNREACHABLE, ICMPV6_UNREACH_ADMIN) => {
            (ICMP_DEST_UNREACHABLE, 13u8) // Communication administratively prohibited
        }
        (ICMPV6_DEST_UNREACHABLE, ICMPV6_UNREACH_ADDR) => {
            (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_HOST)
        }
        (ICMPV6_DEST_UNREACHABLE, ICMPV6_UNREACH_PORT) => {
            (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_PORT)
        }
        (ICMPV6_PACKET_TOO_BIG, _) => (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_NEEDFRAG),
        (ICMPV6_TIME_EXCEEDED, _) => (ICMP_TIME_EXCEEDED, icmp_code),
        (ICMPV6_PARAM_PROBLEM, _) => (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_PROTOCOL),
        _ => (ICMP_DEST_UNREACHABLE, ICMP_UNREACH_HOST),
    };

    let mut data = Vec::with_capacity(payload.len());
    data.push(new_type);
    data.push(new_code);
    data.push(0); // checksum placeholder
    data.push(0);

    if icmp_type == ICMPV6_PACKET_TOO_BIG {
        // Extract MTU from ICMPv6 and adjust for IPv4
        let mtu_v6 = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let mtu_v4 = mtu_v6.saturating_sub(MTU_ADJ as u32);
        // ICMPv4 fragmentation needed: bytes 4-5 are unused (0), 6-7 are next-hop MTU
        data.push(0);
        data.push(0);
        data.extend_from_slice(&(mtu_v4 as u16).to_be_bytes());
    } else {
        data.extend_from_slice(&payload[4..8]);
    }

    // Translate embedded IPv6 header to IPv4
    let embedded = &payload[8..];
    if embedded.len() >= IPV6_HEADER_LEN {
        let em_tc = ((embedded[0] & 0x0f) << 4) | (embedded[1] >> 4);
        let em_payload_len = u16::from_be_bytes([embedded[4], embedded[5]]);
        let mut em_proto = embedded[6];
        let em_hop_limit = embedded[7];

        let em_src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&embedded[8..24]).unwrap());
        let em_dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&embedded[24..40]).unwrap());

        // Extract IPv4 addresses from the embedded IPv6 addresses
        let prefix_octets = _src4.octets(); // Use the outer source for prefix context
        let _ = prefix_octets; // The embedded addresses should be prefix-mapped
        let em_src4_octets = em_src6.octets();
        let em_dst4_octets = em_dst6.octets();
        let em_src4 = Ipv4Addr::new(
            em_src4_octets[12],
            em_src4_octets[13],
            em_src4_octets[14],
            em_src4_octets[15],
        );
        let em_dst4 = Ipv4Addr::new(
            em_dst4_octets[12],
            em_dst4_octets[13],
            em_dst4_octets[14],
            em_dst4_octets[15],
        );

        if em_proto == IPPROTO_ICMPV6 {
            em_proto = IPPROTO_ICMP;
        }

        let total_len = IPV4_HEADER_LEN as u16 + em_payload_len;

        // Build embedded IPv4 header
        data.push(0x45); // version + IHL
        data.push(em_tc); // TOS
        data.extend_from_slice(&total_len.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes()); // identification
        data.extend_from_slice(&0x4000u16.to_be_bytes()); // flags (DF) + frag offset
        data.push(em_hop_limit); // TTL
        data.push(em_proto); // Protocol
                             // We skip the embedded header checksum — it doesn't need to be valid in ICMP error payloads
        data.extend_from_slice(&0u16.to_be_bytes()); // header checksum placeholder
        data.extend_from_slice(&em_src4.octets());
        data.extend_from_slice(&em_dst4.octets());

        // Append embedded payload (up to 64 bytes of original datagram per RFC 792)
        let em_payload_start = IPV6_HEADER_LEN;
        let em_payload = &embedded[em_payload_start..];
        let copy_len = em_payload.len().min(64);
        data.extend_from_slice(&em_payload[..copy_len]);
    }

    // Recompute ICMPv4 checksum
    data[2] = 0;
    data[3] = 0;
    let cksum = checksum::ipv4_header_checksum(&data);
    data[2] = (cksum >> 8) as u8;
    data[3] = (cksum & 0xff) as u8;

    Ok((IPPROTO_ICMP, data))
}

/// Determine whether a raw packet from the TUN device is IPv4 or IPv6.
pub fn detect_ip_version(packet: &[u8]) -> Option<u8> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => Some(4),
        6 => Some(6),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config() -> ParsedConfig {
        ParsedConfig {
            tun_device: "test0".to_string(),
            prefix: "2001:db8:1:ffff::".parse().unwrap(),
            ipv4_addr: "192.168.255.1".parse().unwrap(),
            map4to6: HashMap::new(),
            map6to4: HashMap::new(),
        }
    }

    #[test]
    fn test_detect_version() {
        assert_eq!(detect_ip_version(&[0x45, 0x00]), Some(4));
        assert_eq!(detect_ip_version(&[0x60, 0x00]), Some(6));
        assert_eq!(detect_ip_version(&[0x30]), None);
        assert_eq!(detect_ip_version(&[]), None);
    }

    #[test]
    fn test_icmp_echo_4to6_roundtrip() {
        let config = test_config();

        // Build a minimal ICMPv4 echo request packet
        let src = Ipv4Addr::new(198, 51, 100, 1);
        let dst = Ipv4Addr::new(192, 0, 2, 1);

        // ICMP echo request: type=8, code=0, checksum, id=0x1234, seq=0x0001
        let icmp_payload = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let mut icmp = icmp_payload.to_vec();
        // Fix checksum
        icmp[2] = 0;
        icmp[3] = 0;
        let cksum = checksum::ipv4_header_checksum(&icmp);
        icmp[2] = (cksum >> 8) as u8;
        icmp[3] = (cksum & 0xff) as u8;

        let total_len = (20 + icmp.len()) as u16;
        let mut pkt = vec![
            0x45, 0x00, // version/ihl, tos
        ];
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // id, flags+frag (DF)
        pkt.push(64); // TTL
        pkt.push(IPPROTO_ICMP);
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());

        // Fix IPv4 header checksum
        let hdr_cksum = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (hdr_cksum >> 8) as u8;
        pkt[11] = (hdr_cksum & 0xff) as u8;

        pkt.extend_from_slice(&icmp);

        // Translate 4→6
        let result = translate_4to6(&config, &pkt).unwrap();
        assert_eq!(detect_ip_version(&result.data), Some(6));

        // The translated packet should be valid IPv6
        assert!(result.data.len() >= IPV6_HEADER_LEN);
        assert_eq!(result.data[6], IPPROTO_ICMPV6); // next header

        // Translate back 6→4
        let back = translate_6to4(&config, &result.data).unwrap();
        assert_eq!(detect_ip_version(&back.data), Some(4));
        // TTL should be decremented twice (once each way)
        assert_eq!(back.data[8], 62);
    }
}
