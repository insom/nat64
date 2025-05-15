use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use nix::fcntl::OFlag;

const TUN_PATH: &str = "/dev/net/tun";

// ioctl constants
const TUNSETIFF: u64 = 0x400454ca;

// TUN flags
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

/// ioctl request structure for TUN/TAP
#[repr(C)]
struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: u16,
    _pad: [u8; 22],
}

/// ioctl request for getting MTU
#[repr(C)]
struct IfReqMtu {
    ifr_name: [u8; 16],
    ifr_mtu: i32,
    _pad: [u8; 20],
}

nix::ioctl_write_ptr_bad!(tun_set_iff, TUNSETIFF, IfReq);

const SIOCGIFMTU: u64 = 0x8921;
nix::ioctl_read_bad!(get_if_mtu, SIOCGIFMTU, IfReqMtu);

/// An opened TUN device.
pub struct TunDevice {
    file: File,
    name: String,
    pub mtu: u16,
}

impl TunDevice {
    /// Open (or create) a TUN device with the given name.
    /// The device is opened without the packet-info header (IFF_NO_PI),
    /// so reads/writes are raw IP packets.
    pub fn open(dev_name: &str) -> io::Result<Self> {
        let fd = nix::fcntl::open(
            TUN_PATH,
            OFlag::O_RDWR | OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(io::Error::other)?;

        // Safety: we just opened the fd
        let file = unsafe { File::from_raw_fd(fd) };

        let mut ifreq = IfReq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };

        let name_bytes = dev_name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifreq.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        unsafe {
            tun_set_iff(file.as_raw_fd(), &ifreq)
                .map_err(io::Error::other)?;
        }

        let actual_name = {
            let end = ifreq.ifr_name.iter().position(|&b| b == 0).unwrap_or(16);
            String::from_utf8_lossy(&ifreq.ifr_name[..end]).to_string()
        };

        // Query MTU via a socket ioctl
        let mtu = Self::query_mtu(&actual_name)?;

        log::info!("Opened TUN device '{}' with MTU {}", actual_name, mtu);

        Ok(TunDevice {
            file,
            name: actual_name,
            mtu,
        })
    }

    fn query_mtu(dev_name: &str) -> io::Result<u16> {
        let sock = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Inet,
            nix::sys::socket::SockType::Datagram,
            nix::sys::socket::SockFlag::empty(),
            None,
        )
        .map_err(io::Error::other)?;

        let mut ifreq = IfReqMtu {
            ifr_name: [0u8; 16],
            ifr_mtu: 0,
            _pad: [0u8; 20],
        };
        let name_bytes = dev_name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifreq.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        unsafe {
            get_if_mtu(sock.as_raw_fd(), &mut ifreq)
                .map_err(io::Error::other)?;
        }

        Ok(ifreq.ifr_mtu as u16)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Read a packet from the TUN device. Returns the number of bytes read,
    /// or `WouldBlock` if no packet is available.
    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    /// Write a packet to the TUN device.
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }
}
