use std::net::{Ipv4Addr, Ipv6Addr};

/// Standard one's complement checksum over a byte slice.
pub fn ones_complement_sum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

/// Fold a 32-bit accumulator into a 16-bit one's complement value.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Compute the IPv4 header checksum. Returns the checksum in network (big-endian) order.
/// `header` must be the raw IPv4 header bytes (with the checksum field zeroed).
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    !fold(ones_complement_sum(header))
}

/// Compute a checksum over a pseudo-header + payload for IPv6 (TCP/UDP/ICMPv6).
pub fn ipv6_pseudo_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Source address
    for pair in src.octets().chunks(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    // Destination address
    for pair in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    // Upper-layer packet length (32-bit)
    let len = payload.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    // Next header / protocol
    sum += protocol as u32;
    // Payload
    sum += ones_complement_sum(payload);

    !fold(sum)
}

/// Incremental checksum conversion when translating addresses from IPv4 to IPv6.
///
/// Given the original transport checksum, remove the contribution of the old IPv4
/// src/dst and add the contribution of the new IPv6 src/dst.
pub fn convert_checksum_4to6(
    original: u16,
    old_src4: &Ipv4Addr,
    old_dst4: &Ipv4Addr,
    new_src6: &Ipv6Addr,
    new_dst6: &Ipv6Addr,
) -> u16 {
    let mut sum: u32 = !original as u32;

    // Subtract old IPv4 addresses (add their complement)
    for pair in old_src4.octets().chunks(2) {
        sum += !u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    for pair in old_dst4.octets().chunks(2) {
        sum += !u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    // Add new IPv6 addresses
    for pair in new_src6.octets().chunks(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    for pair in new_dst6.octets().chunks(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }

    !fold(sum)
}

/// Incremental checksum conversion when translating addresses from IPv6 to IPv4.
pub fn convert_checksum_6to4(
    original: u16,
    old_src6: &Ipv6Addr,
    old_dst6: &Ipv6Addr,
    new_src4: &Ipv4Addr,
    new_dst4: &Ipv4Addr,
) -> u16 {
    let mut sum: u32 = !original as u32;

    // Subtract old IPv6 addresses
    for pair in old_src6.octets().chunks(2) {
        sum += !u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    for pair in old_dst6.octets().chunks(2) {
        sum += !u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    // Add new IPv4 addresses
    for pair in new_src4.octets().chunks(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    for pair in new_dst4.octets().chunks(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }

    !fold(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_header_checksum() {
        // Minimal IPv4 header (20 bytes) with checksum field zeroed
        let mut hdr = [
            0x45, 0x00, 0x00, 0x3c, // ver+ihl, tos, total len
            0x1c, 0x46, 0x40, 0x00, // ident, flags+frag
            0x40, 0x06, 0x00, 0x00, // ttl, proto(TCP), checksum=0
            0xac, 0x10, 0x0a, 0x63, // src 172.16.10.99
            0xac, 0x10, 0x0a, 0x0c, // dst 172.16.10.12
        ];
        let cksum = ipv4_header_checksum(&hdr);
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = cksum as u8;
        // Verify: checksum of entire header including checksum field should be 0
        assert_eq!(fold(ones_complement_sum(&hdr)), 0xffff);
    }

    #[test]
    fn test_convert_roundtrip() {
        let src4 = Ipv4Addr::new(192, 0, 2, 1);
        let dst4 = Ipv4Addr::new(198, 51, 100, 1);
        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc000, 0x0201);
        let dst6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc633, 0x6401);

        let original: u16 = 0xabcd;
        let converted = convert_checksum_4to6(original, &src4, &dst4, &src6, &dst6);
        let back = convert_checksum_6to4(converted, &src6, &dst6, &src4, &dst4);
        assert_eq!(back, original);
    }
}
