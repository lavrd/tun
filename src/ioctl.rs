use std::{io::Error as IoError, os::fd::AsRawFd};

use libc::{c_ulong, c_void};

use crate::{fd::Fd, Error};

pub(crate) fn ioctl<T>(fd: &Fd, req: c_ulong, arg: &mut T) -> Result<(), Error> {
    let arg: *mut c_void = arg as *mut _ as *mut c_void;
    let res = unsafe { libc::ioctl(fd.inner.as_raw_fd(), req, arg) };
    if res < 0 {
        return Err(format!("failed to do ioctl call: {}", IoError::last_os_error()).into());
    }
    Ok(())
}
