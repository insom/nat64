# nat64

A static NAT64 translator written in Rust. Allows IPv6-only hosts to reach IPv4
destinations by translating packets through a TUN device on Linux.

Supports both RFC 6052 prefix-based address synthesis and explicit static 1:1
IPv4:IPv6 mappings.

## Install

```sh
cargo install nat64
```

Or from source:

```sh
cargo install --path .
```

## TUN device setup

```sh
ip tuntap add mode tun nat64
ip link set nat64 up
ip addr add 192.168.255.1/32 dev nat64
ip addr add 2001:db8:1::1/128 dev nat64
ip route add 192.0.2.0/24 dev nat64
ip route add 2001:db8:1:ffff::/96 dev nat64
```

## Configuration

Copy `nat64.toml.example` to `nat64.toml` and edit as needed:

```toml
tun_device = "nat64"

# NAT64 /96 prefix — IPv4 addresses are embedded in the last 32 bits
prefix = "2001:db8:1:ffff::"

# Local IPv4 address used as source for ICMP errors
ipv4_addr = "192.168.255.1"

# Optional static 1:1 mappings
[[map]]
ipv4 = "192.0.2.10"
ipv6 = "2001:db8:1:4444::10"
```

## Usage

```sh
nat64 /etc/nat64.toml
```

Set the `RUST_LOG` environment variable to control log verbosity:

```sh
RUST_LOG=debug nat64 /etc/nat64.toml
```

## How it works

- IPv4 packets arriving on the TUN device are translated to IPv6 and written back.
- IPv6 packets are translated to IPv4 and written back.
- Without static mappings, destination IPv4 addresses are synthesized into the
  configured /96 prefix per [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052).
- Static `[[map]]` entries override prefix-based synthesis for specific addresses.

## License

GPL-3.0 — see [LICENSE](LICENSE).
