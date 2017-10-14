use std::io;
use std::net::UdpSocket;

pub trait WritevExt {
    fn writev(&self, bufs: [&[u8]; 2]) -> io::Result<usize>;
    fn readv(&self, bufs: [&mut [u8]; 2]) -> io::Result<usize>;
}

#[cfg(unix)]
mod imp {
    use libc;
    use std::os::unix::io::AsRawFd;

    use super::*;

    impl WritevExt for UdpSocket {
        fn writev(&self, bufs: [&[u8]; 2]) -> io::Result<usize> {
            unsafe {
                let iovecs = [
                    libc::iovec {
                        iov_base: bufs[0].as_ptr() as *const _ as *mut _,
                        iov_len: bufs[0].len(),
                    },
                    libc::iovec {
                        iov_base: bufs[1].as_ptr() as *const _ as *mut _,
                        iov_len: bufs[1].len(),
                    },
                ];
                let r = libc::writev(self.as_raw_fd(), iovecs.as_ptr(), 2);
                if r < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(r as usize)
                }
            }
        }

        fn readv(&self, bufs: [&mut [u8]; 2]) -> io::Result<usize> {
            unsafe {
                let mut iovecs = [
                    libc::iovec {
                        iov_base: bufs[0].as_mut_ptr() as *mut _,
                        iov_len: bufs[0].len(),
                    },
                    libc::iovec {
                        iov_base: bufs[1].as_mut_ptr() as *mut _,
                        iov_len: bufs[1].len(),
                    },
                ];
                let r = libc::readv(self.as_raw_fd(), iovecs.as_mut_ptr(), 2);
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
        fn writev(&self, bufs: [&[u8]; 2]) -> io::Result<usize> {
            unsafe {
                let mut wsabufs = [
                    winapi::WSABUF {
                        len: bufs[0].len() as winapi::u_long,
                        buf: bufs[0].as_ptr() as *const _ as *mut _,
                    },
                    winapi::WSABUF {
                        len: bufs[1].len() as winapi::u_long,
                        buf: bufs[1].as_ptr() as *const _ as *mut _,
                    },
                ];
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

        fn readv(&self, bufs: [&mut [u8]; 2]) -> io::Result<usize> {
            unsafe {
                let mut wsabufs = [
                    winapi::WSABUF {
                        len: bufs[0].len() as winapi::u_long,
                        buf: bufs[0].as_mut_ptr() as *mut _,
                    },
                    winapi::WSABUF {
                        len: bufs[1].len() as winapi::u_long,
                        buf: bufs[1].as_mut_ptr() as *mut _,
                    },
                ];
                let mut recved = 0;
                let mut flags = 0;
                let r = ws2_32::WSARecv(
                    self.as_raw_socket(),
                    wsabufs.as_mut_ptr(),
                    bufs.len() as winapi::DWORD,
                    &mut recved,
                    &mut flags,
                    ptr::null_mut(),
                    None,
                );
                if r == 0 {
                    Ok(recved as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }
}
