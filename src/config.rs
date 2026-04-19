use serde::Deserialize;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Top-level configuration for nat64.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// TUN device name (e.g. "nat64")
    #[serde(default = "default_tun_device")]
    pub tun_device: String,

    /// NAT64 prefix — must be a /96. Specified as "2001:db8:1:ffff::" (the /96 is implicit).
    pub prefix: String,

    /// TAYGA-style local IPv4 address used as the source for ICMP errors
    pub ipv4_addr: String,

    /// Static 1:1 address mappings: IPv4 → IPv6
    #[serde(default)]
    pub map: Vec<StaticMapping>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StaticMapping {
    pub ipv4: String,
    pub ipv6: String,
}

fn default_tun_device() -> String {
    "nat64".to_string()
}

/// Parsed and validated configuration.
#[derive(Debug)]
pub struct ParsedConfig {
    pub tun_device: String,
    pub prefix: Ipv6Addr,
    pub ipv4_addr: Ipv4Addr,
    /// Static maps: IPv4 → IPv6 and IPv6 → IPv4
    pub map4to6: HashMap<Ipv4Addr, Ipv6Addr>,
    pub map6to4: HashMap<Ipv6Addr, Ipv4Addr>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<ParsedConfig, String> {
        let contents =
            std::fs::read_to_string(&path).map_err(|e| format!("Cannot read config: {}", e))?;
        let raw: Config = toml::from_str(&contents).map_err(|e| format!("Parse error: {}", e))?;
        raw.validate()
    }

    fn validate(self) -> Result<ParsedConfig, String> {
        let prefix: Ipv6Addr = self
            .prefix
            .parse()
            .map_err(|e| format!("Invalid prefix '{}': {}", self.prefix, e))?;

        // Verify it's a valid /96 — last 32 bits must be zero
        let octets = prefix.octets();
        if octets[12] != 0 || octets[13] != 0 || octets[14] != 0 || octets[15] != 0 {
            return Err(format!(
                "Prefix '{}' is not a valid /96 (last 32 bits must be zero)",
                self.prefix
            ));
        }

        let ipv4_addr: Ipv4Addr = self
            .ipv4_addr
            .parse()
            .map_err(|e| format!("Invalid ipv4_addr '{}': {}", self.ipv4_addr, e))?;

        let mut map4to6 = HashMap::new();
        let mut map6to4 = HashMap::new();

        for m in &self.map {
            let v4: Ipv4Addr = m
                .ipv4
                .parse()
                .map_err(|e| format!("Invalid map IPv4 '{}': {}", m.ipv4, e))?;
            let v6: Ipv6Addr = m
                .ipv6
                .parse()
                .map_err(|e| format!("Invalid map IPv6 '{}': {}", m.ipv6, e))?;

            if map4to6.contains_key(&v4) {
                return Err(format!("Duplicate IPv4 mapping for {}", v4));
            }
            if map6to4.contains_key(&v6) {
                return Err(format!("Duplicate IPv6 mapping for {}", v6));
            }

            map4to6.insert(v4, v6);
            map6to4.insert(v6, v4);
        }

        Ok(ParsedConfig {
            tun_device: self.tun_device,
            prefix,
            ipv4_addr,
            map4to6,
            map6to4,
        })
    }
}

/// Embed an IPv4 address into a /96 prefix to produce a full IPv6 address.
/// The IPv4 address occupies the last 32 bits.
pub fn embed_ipv4_in_prefix(prefix: &Ipv6Addr, addr: &Ipv4Addr) -> Ipv6Addr {
    let mut octets = prefix.octets();
    let v4 = addr.octets();
    octets[12] = v4[0];
    octets[13] = v4[1];
    octets[14] = v4[2];
    octets[15] = v4[3];
    Ipv6Addr::from(octets)
}

/// Extract an IPv4 address from a /96-prefixed IPv6 address.
/// Returns `None` if the first 96 bits don't match the prefix.
pub fn extract_ipv4_from_prefix(prefix: &Ipv6Addr, addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    let p = prefix.octets();
    let a = addr.octets();
    // Check that the first 96 bits (12 bytes) match
    if p[..12] != a[..12] {
        return None;
    }
    Some(Ipv4Addr::new(a[12], a[13], a[14], a[15]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embed_extract() {
        let prefix: Ipv6Addr = "2001:db8:1:ffff::".parse().unwrap();
        let v4 = Ipv4Addr::new(192, 0, 2, 1);
        let v6 = embed_ipv4_in_prefix(&prefix, &v4);
        assert_eq!(v6, "2001:db8:1:ffff::c000:201".parse::<Ipv6Addr>().unwrap());
        let extracted = extract_ipv4_from_prefix(&prefix, &v6).unwrap();
        assert_eq!(extracted, v4);
    }

    #[test]
    fn test_prefix_mismatch() {
        let prefix: Ipv6Addr = "2001:db8:1:ffff::".parse().unwrap();
        let other: Ipv6Addr = "2001:db8:2:ffff::c000:201".parse().unwrap();
        assert!(extract_ipv4_from_prefix(&prefix, &other).is_none());
    }
}
