use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};


/// An opened TUN device.
pub struct TunDevice {
    name: String,
    dev: tun::Device,
}

impl TunDevice {
    /// Open (or create) a TUN device with the given name.
    /// The device is opened without the packet-info header (IFF_NO_PI),
    /// so reads/writes are raw IP packets.
    pub fn open(dev_name: &str) -> io::Result<Self> {

        let mut config = tun::Configuration::default();
        config.up();
        config.tun_name(dev_name);

        #[cfg(target_os = "linux")]
        config.platform_config(|_| {});

        let dev = tun::create(&config)?;
        dev.set_nonblock()?;
        
        let actual_name: String = dev_name.into();

        log::info!("Opened TUN device '{}'", actual_name);

        Ok(TunDevice {
            name: actual_name,
            dev,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fd(&self) -> RawFd {
        self.dev.as_raw_fd()
    }

    /// Read a packet from the TUN device. Returns the number of bytes read,
    /// or `WouldBlock` if no packet is available.
    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.read(buf)
    }

    /// Write a packet to the TUN device.
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.dev.write(buf)
    }
}
