// OpenBSD docs: https://man.openbsd.org/netintro.4

use std::{
    ffi::{CStr, CString},
    io::Error as IoError,
    mem,
    net::Ipv4Addr,
    os::fd::AsRawFd,
    process::Command,
    ptr,
    str::from_utf8,
};

use ipnet::Ipv4Net;
use libc::{
    c_char, c_int, c_short, c_uint, c_ulong, c_ushort, c_void, connect, sockaddr_in, socklen_t,
    AF_INET, AF_SYSTEM, AF_SYS_CONTROL, CTLIOCGINFO, IFNAMSIZ, IPPROTO_IP, PF_SYSTEM, SIOCGIFADDR,
    SOCK_DGRAM, SYSPROTO_CONTROL,
};
use log::{debug, trace};

use crate::{
    fd::Fd, ioctl::ioctl, Device as IDevice, DeviceInfo, Error, DEFAULT_FLAGS, DEFAULT_MTU,
};

const UTUN_OPT_IFNAME: c_int = 2;
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

// Unfortunately these constants are not present in libc for macOS.
const SIOCAIFADDR: c_ulong = 0x8040691a;
const SIOCGIFMTU: c_ulong = 0xc0206933;
const SIOCGIFFLAGS: c_ulong = 0xc0206911;
const SIOCGIFNETMASK: c_ulong = 0xc0206925;
const SIOCSIFMTU: c_ulong = 0x80206934;
const SIOCSIFFLAGS: c_ulong = 0x80206910;

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq {
    ifrn: ifr_name,
    ifru: ifr_ifru,
}

#[repr(C)]
union ifr_name {
    name: [c_char; IFNAMSIZ],
}

#[repr(C)]
#[derive(Clone, Copy)]
union ifr_ifru {
    ifru_addr: sockaddr,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    ifru_data: *mut c_void,
    ifru_devmtu: ifdevmtu,
    ifru_wake_flags: c_uint,
    ifru_route_refcnt: c_uint,
    ifru_cap: [c_int; 2],
    ifru_functional_type: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
struct ifdevmtu {
    ifdm_current: c_int,
    ifdm_min: c_int,
    ifdm_max: c_int,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifaliasreq {
    ifra_name: [c_char; IFNAMSIZ],
    ifra_addr: sockaddr,
    ifra_dstaddr: sockaddr,
    ifra_mask: sockaddr,
}

// We don't use libc::sockaddr because it stores sa_data as [i8; 14].
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
struct sockaddr {
    sa_len: u8,
    sa_family: u8,
    sa_data: [u8; 14],
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ctl_info {
    ctl_id: c_uint,
    ctl_name: [c_char; 96],
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct sockaddr_ctl {
    sc_len: c_char,
    sc_family: c_char,
    ss_sysaddr: c_ushort,
    sc_id: c_uint,
    sc_unit: c_uint,
    sc_reserved: [c_uint; 5],
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq_mtu {
    ifrn: ifr_name,
    mtu: c_int,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq_flags {
    ifrn: ifr_name,
    flags: c_short,
}

pub(crate) struct Device {
    name: CString,
    tun_fd: Fd,
    ip_fd: Fd,
}

impl IDevice for Device {
    fn new(name: &str, ip: Ipv4Net) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let tun_fd = Fd::new(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)?;
        let ip_fd = Fd::new(AF_INET, SOCK_DGRAM, IPPROTO_IP)?;

        let id: u8 = {
            if name.len() > IFNAMSIZ {
                return Err("name is too long".into());
            }
            // In macOS you are not allowed to create tun device with another name.
            if !name.starts_with("utun") {
                return Err("name should start from utun".into());
            }
            let mut id: u8 = name[4..].parse()?;
            // We need to increase by 1 otherwise lower tun id will be created.
            id += 1;
            id
        };
        trace!("device id: {}", id - 1);

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: {
                let mut buf = [0; 96];
                for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buf.iter_mut()) {
                    *o = *i as _;
                }
                buf
            },
        };
        ioctl(&tun_fd, CTLIOCGINFO, &mut info)
            .map_err(|e| format!("failed to get ctl info: {}", e))?;
        trace!("device ctl id: {}", info.ctl_id);

        let addr = sockaddr_ctl {
            sc_id: info.ctl_id,
            sc_len: mem::size_of::<sockaddr_ctl>() as _,
            sc_family: AF_SYSTEM as i8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_unit: id as c_uint,
            sc_reserved: [0; 5],
        };
        if unsafe {
            connect(
                tun_fd.inner.as_raw_fd(),
                &addr as *const sockaddr_ctl as *const libc::sockaddr,
                mem::size_of_val(&addr) as socklen_t,
            )
        } < 0
        {
            return Err(format!("failed to connect: {}", IoError::last_os_error()).into());
        }

        let name: CString = unsafe {
            let mut name = [0u8; 64];
            let mut name_len: socklen_t = 64;
            if libc::getsockopt(
                tun_fd.inner.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                &mut name as *mut _ as *mut c_void,
                &mut name_len as *mut socklen_t,
            ) < 0
            {
                return Err(format!("failed to getsockopt: {}", IoError::last_os_error()).into());
            };
            let name: String =
                CStr::from_ptr(name.as_ptr() as *const c_char).to_string_lossy().into();
            CString::new(name)?
        };
        trace!("device name: {}", name.to_string_lossy());

        let mut if_alias_req: ifaliasreq = unsafe { mem::zeroed() };
        if_alias_req.ifra_addr = sockaddr {
            sa_len: 16,
            sa_family: AF_INET as u8,
            sa_data: [0; 14],
        };
        if_alias_req.ifra_dstaddr = sockaddr {
            sa_len: 16,
            sa_family: AF_INET as u8,
            sa_data: [0; 14],
        };
        if_alias_req.ifra_mask = sockaddr {
            sa_len: 16,
            sa_family: AF_INET as u8,
            sa_data: [0; 14],
        };
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr() as *const c_char,
                if_alias_req.ifra_name.as_mut_ptr(),
                name.as_bytes().len(),
            );
            // See the bytes magic in https://docs.freebsd.org/en/books/developers-handbook/sockets/
            if_alias_req.ifra_addr.sa_data[2] = ip.addr().octets()[0];
            if_alias_req.ifra_addr.sa_data[3] = ip.addr().octets()[1];
            if_alias_req.ifra_addr.sa_data[4] = ip.addr().octets()[2];
            if_alias_req.ifra_addr.sa_data[5] = ip.addr().octets()[3];
            if_alias_req.ifra_dstaddr.sa_data[2] = ip.addr().octets()[0];
            if_alias_req.ifra_dstaddr.sa_data[3] = ip.addr().octets()[1];
            if_alias_req.ifra_dstaddr.sa_data[4] = ip.addr().octets()[2];
            if_alias_req.ifra_dstaddr.sa_data[5] = ip.addr().octets()[3];
            if_alias_req.ifra_mask.sa_data[2] = ip.netmask().octets()[0];
            if_alias_req.ifra_mask.sa_data[3] = ip.netmask().octets()[1];
            if_alias_req.ifra_mask.sa_data[4] = ip.netmask().octets()[2];
            if_alias_req.ifra_mask.sa_data[5] = ip.netmask().octets()[3];
        };
        // Set interface alias.
        ioctl(&ip_fd, SIOCAIFADDR, &mut if_alias_req)?;
        trace!("alias was set");

        // Set mtu size.
        let mut if_req_mtu: ifreq_mtu = unsafe { mem::zeroed() };
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr() as *const c_char,
                if_req_mtu.ifrn.name.as_mut_ptr(),
                name.to_bytes().len(),
            )
        };
        if_req_mtu.mtu = DEFAULT_MTU;
        ioctl(&ip_fd, SIOCSIFMTU, &mut if_req_mtu)?;
        trace!("mtu was set");

        // Set flags.
        let mut if_req_flags: ifreq_flags = unsafe { mem::zeroed() };
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr() as *const c_char,
                if_req_flags.ifrn.name.as_mut_ptr(),
                name.to_bytes().len(),
            )
        };
        if_req_flags.flags = DEFAULT_FLAGS;
        ioctl(&ip_fd, SIOCSIFFLAGS, &mut if_req_flags)?;
        trace!("flags was set");

        // Could be refactored with a syscall:
        // - https://www.cs.cmu.edu/~srini/15-441/F01.full/www/assignments/P2/htmlsim_split/node20.html
        // - https://www.netbsd.org/docs/internals/en/chap-networking-core.html
        // - https://man.openbsd.org/route.4
        // Ex: sudo /sbin/route -n add -net 10.0.0.0/16 -interface utun10
        let output = Command::new("/sbin/route")
            .args(vec![
                "-n",
                "add",
                &ip.to_string(),
                "-interface",
                &name.to_string_lossy(),
            ])
            .output()?;
        trace!(
            "output after route cmd: stdout: {:?}; stderr: {:?}",
            from_utf8(&output.stdout),
            from_utf8(&output.stderr)
        );
        trace!("route was added");

        debug!("device was created");
        Ok(Self {
            name,
            tun_fd,
            ip_fd,
        })
    }

    fn info(&self) -> Result<DeviceInfo, Error> {
        let mut if_req: ifreq = unsafe { mem::zeroed() };
        unsafe {
            ptr::copy_nonoverlapping(
                self.name.as_ptr() as *const c_char,
                if_req.ifrn.name.as_mut_ptr(),
                self.name.to_bytes().len(),
            )
        };

        let netmask: u32 = {
            ioctl(&self.ip_fd, SIOCGIFNETMASK, &mut if_req)?;
            let netmask: sockaddr_in = unsafe { mem::transmute(if_req.ifru.ifru_addr) };
            u32::from_be(netmask.sin_addr.s_addr)
        };

        ioctl(&self.ip_fd, SIOCGIFADDR, &mut if_req)?;
        let name: String = unsafe {
            let last_non_zero_idx = if_req.ifrn.name.iter().rposition(|&x| x != 0).unwrap_or(0) + 1;
            from_utf8(
                if_req.ifrn.name[..last_non_zero_idx]
                    .to_vec()
                    .iter()
                    .map(|e| *e as u8)
                    .collect::<Vec<u8>>()
                    .as_slice(),
            )
            .unwrap()
            .to_string()
        };
        let addr = unsafe { sock_addr_to_ip_addr(if_req.ifru.ifru_addr, netmask) }?;
        let dest = unsafe { sock_addr_to_ip_addr(if_req.ifru.ifru_dstaddr, netmask) }?;
        let broadcast = unsafe { sock_addr_to_ip_addr(if_req.ifru.ifru_broadaddr, netmask) }?;

        let flags = {
            ioctl(&self.ip_fd, SIOCGIFFLAGS, &mut if_req)?;
            unsafe { if_req.ifru.ifru_flags }
        };

        let mtu = {
            unsafe {
                ioctl(&self.ip_fd, SIOCGIFMTU, &mut if_req)?;
                if_req.ifru.ifru_mtu as usize
            }
        };

        Ok(DeviceInfo {
            name,
            addr,
            dest,
            broadcast,
            flags,
            mtu,
        })
    }

    fn fd(&mut self) -> &mut Fd {
        &mut self.tun_fd
    }
}

fn sock_addr_to_ip_addr(addr: sockaddr, netmask: u32) -> Result<Ipv4Net, Error> {
    // See the bytes magic in https://docs.freebsd.org/en/books/developers-handbook/sockets/.
    let raw_addr: [u8; 4] = addr.sa_data[2..6].try_into()?;
    let addr: Ipv4Addr = Ipv4Addr::from(raw_addr);
    let netmask: Ipv4Addr = Ipv4Addr::from(netmask);
    Ok(Ipv4Net::with_netmask(addr, netmask)?)
}
