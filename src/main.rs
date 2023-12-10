use ipnet::Ipv4Net;
use libc::{IFF_NOARP, IFF_POINTOPOINT, IFF_RUNNING, IFF_UP};

use fd::Fd;

mod fd;
mod ioctl;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

// Default minimal transmit unit in bytes.
pub(crate) const DEFAULT_MTU: i32 = 2300;
// IFF_UP - is used to bring interface up to indicate that interface is active and ready.
// IFF_POINTOPOINT - point to point link.
// IFF_RUNNING - indicate that interface is up and operational. So to start transmit data.
// IFF_NOARP - disable Address Resolution Protocol as we don't need it because of point-to-point link.
pub(crate) const DEFAULT_FLAGS: i16 = (IFF_UP | IFF_POINTOPOINT | IFF_RUNNING | IFF_NOARP) as i16;

type Error = Box<dyn std::error::Error>;

#[cfg_attr(test, derive(Debug))]
struct DeviceInfo {
    name: String,
    addr: Ipv4Net,
    dest: Ipv4Net,
    broadcast: Ipv4Net,
    flags: i16,
    mtu: usize,
}

trait Device {
    fn new(name: &str, ip: Ipv4Net) -> Result<Self, Error>
    where
        Self: Sized;
    fn info(&self) -> Result<DeviceInfo, Error>;
    fn fd(&mut self) -> &mut Fd;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.fd().write(buf)
    }
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.fd().read()
    }
}

fn main() {}

#[cfg(test)]
mod tests {
    use std::{
        net::{SocketAddr, TcpStream},
        time::Duration,
    };

    use log::{debug, info, warn, LevelFilter};

    use crate::*;
    #[cfg(target_os = "linux")]
    use linux::Device as linuxDevice;
    #[cfg(target_os = "macos")]
    use macos::Device as macOSDevice;

    const DEVICE_NAME: &str = "utun10";
    const DEVICE_IP: &str = "10.0.0.1/16";

    #[test]
    fn test() {
        env_logger::builder().filter_level(LevelFilter::Trace).is_test(true).init();

        let device_ip: Ipv4Net = DEVICE_IP.parse().unwrap();

        #[cfg(target_os = "macos")]
        let mut device = macOSDevice::new(DEVICE_NAME, device_ip).unwrap();
        #[cfg(target_os = "linux")]
        let mut device = linuxDevice::new(DEVICE_NAME, ip).unwrap();

        info!("created device with {} ip and {} mask", device_ip.addr(), device_ip.netmask());

        if let Err(e) = TcpStream::connect_timeout(
            &"10.0.0.2:8080".parse::<SocketAddr>().unwrap(),
            Duration::from_millis(100),
        ) {
            // It is okay error as we don't have server on this addr.
            warn!("failed to connect: {}", e);
        }

        let buf = device.read().unwrap().unwrap();
        // 69 means IP version is 4 and IP header length is 20 bytes.
        let idx = buf.iter().position(|b| *b == 69).unwrap();
        let buf = &buf[idx..];
        assert_eq!(69, buf[0]);
        assert_eq!([10, 0, 0, 1], buf[12..16]);
        assert_eq!([10, 0, 0, 2], buf[16..20]);
        assert_eq!([31, 144], buf[22..24]);

        #[cfg(target_os = "macos")]
        test_device_info(&device)
    }

    #[cfg(target_os = "macos")]
    fn test_device_info(device: &impl Device) {
        let info = device.info().unwrap();
        assert_eq!(DEVICE_NAME, &info.name);
        assert_eq!(DEVICE_IP, &info.addr.to_string());
        assert_eq!(DEVICE_IP, &info.dest.to_string());
        assert_eq!(DEVICE_IP, &info.broadcast.to_string());
        assert_eq!(-32559, info.flags);
        assert_eq!(2300, info.mtu);
        debug!("{:?}", info);
    }
}
