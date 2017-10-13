use std::io;
use std::net::UdpSocket;
use std::mem;

pub trait WritevExt {
    fn writev(&self, bufs: &[&[u8]]) -> io::Result<usize>;
}

#[cfg(unix)]
mod imp {
    use libc;
    use std::os::unix::io::AsRawFd;

    use super::*;

    impl WritevExt for UdpSocket {
        fn writev(&self, bufs: &[&[u8]]) -> io::Result<usize> {
            unsafe {
                assert!(bufs.len() <= 2);
                let mut iovecs: [libc::iovec; 2] = mem::uninitialized();
                for (buf, iovec) in bufs.iter().zip(&mut iovecs) {
                    iovec.iov_base = buf.as_ptr() as *const _ as *mut _;
                    iovec.iov_len = buf.len();
                }
                let r = libc::writev(self.as_raw_fd(), iovecs.as_ptr(), bufs.len() as libc::c_int);
                if r < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(r as usize)
                }
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use winapi;
    use ws2_32;
    use std::os::windows::io::AsRawSocket;
    use std::ptr;

    use super::*;

    impl WritevExt for UdpSocket {
        fn writev(&self, bufs: &[&[u8]]) -> io::Result<usize> {
            unsafe {
                assert!(bufs.len() <= 2);
                let mut wsabufs: [winapi::WSABUF; 2] = mem::uninitialized();
                for (buf, wsabuf) in bufs.iter().zip(&mut wsabufs) {
                    wsabuf.len = buf.len() as winapi::u_long;
                    wsabuf.buf = buf.as_ptr() as *mut u8 as *mut winapi::CHAR;
                }
                let mut sent = 0;
                let r = ws2_32::WSASend(
                    self.as_raw_socket(),
                    wsabufs.as_mut_ptr(),
                    bufs.len() as winapi::DWORD,
                    &mut sent,
                    0,
                    ptr::null_mut(),
                    None,
                );
                if r == 0 {
                    Ok(sent as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }
}
