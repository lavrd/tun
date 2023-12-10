use std::{
    fs::File,
    io::{Error as IoError, ErrorKind, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
};

use libc::{c_int, close, socket};
use log::{debug, error};

use crate::Error;

pub(crate) struct Fd {
    pub(crate) inner: File,
}

impl Fd {
    pub(crate) fn new(domain: c_int, ty: c_int, protocol: c_int) -> Result<Self, Error> {
        let inner = unsafe { socket(domain, ty, protocol) };
        if inner < 0 {
            return Err(
                format!("failed to open file descriptor: {}", IoError::last_os_error()).into()
            );
        }
        Fd::from_raw(inner)
    }

    pub(crate) fn from_raw(inner: i32) -> Result<Self, Error> {
        if inner < 0 {
            return Err(
                format!("failed to open file descriptor: {}", IoError::last_os_error()).into()
            );
        }
        let inner = unsafe { File::from_raw_fd(inner) };
        Ok(Self { inner })
    }

    pub(crate) fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        Ok(self.inner.write(buf)?)
    }

    pub(crate) fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let mut buf = vec![0; 1024];
        let n = match self.inner.read(&mut buf) {
            Ok(n) => n,
            // This errors indicates that read operation should block current thread,
            // but no data available in file descriptor.
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => return Err(format!("failed to read from file descriptor: {}", e).into()),
        };
        // Delete empty bytes from buffer.
        buf.truncate(n);
        Ok(Some(buf))
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        let res = unsafe { close(self.inner.as_raw_fd()) };
        if res != 0 {
            error!(
                "failed to close file descriptor: {}: {}",
                self.inner.as_raw_fd(),
                IoError::last_os_error()
            );
            return;
        }
        debug!("file descriptor was closed: {}", self.inner.as_raw_fd());
    }
}
