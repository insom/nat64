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

    // Simple payload translation for TCP/UDP (just copy and fix checksum)
    let (next_header, translated_payload) = match protocol {
        IPPROTO_TCP => {
            let mut data = payload.to_vec();
            if data.len() >= 18 {
                let old_cksum = u16::from_be_bytes([data[16], data[17]]);
                let new_cksum = checksum::convert_checksum_4to6(old_cksum, &src4, &dst4, &src6, &dst6);
                data[16] = (new_cksum >> 8) as u8;
                data[17] = (new_cksum & 0xff) as u8;
            }
            (IPPROTO_TCP, data)
        }
        IPPROTO_UDP => {
            let mut data = payload.to_vec();
            if data.len() >= 8 {
                let old_cksum = u16::from_be_bytes([data[6], data[7]]);
                if old_cksum == 0 {
                    // UDP over IPv6 requires a checksum
                    data[6] = 0;
                    data[7] = 0;
                    let new_cksum = checksum::ipv6_pseudo_checksum(&src6, &dst6, IPPROTO_UDP, &data);
                    let new_cksum = if new_cksum == 0 { 0xffff } else { new_cksum };
                    data[6] = (new_cksum >> 8) as u8;
                    data[7] = (new_cksum & 0xff) as u8;
                } else {
                    let new_cksum = checksum::convert_checksum_4to6(old_cksum, &src4, &dst4, &src6, &dst6);
                    let new_cksum = if new_cksum == 0 { 0xffff } else { new_cksum };
                    data[6] = (new_cksum >> 8) as u8;
                    data[7] = (new_cksum & 0xff) as u8;
                }
            }
            (IPPROTO_UDP, data)
        }
        _ => {
            log::debug!("Passing through protocol {} without checksum fixup", protocol);
            (protocol, payload.to_vec())
        }
    };

    // Decide whether we need a fragment header
    let is_fragment = more_fragments || frag_offset != 0;
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
