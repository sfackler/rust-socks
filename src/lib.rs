//! SOCKS proxy clients
#![doc(html_root_url="https://sfackler.github.io/rust-socks/doc/v0.1.0")]
#![warn(missing_docs)]

extern crate byteorder;

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::io::{self, Read, Write, BufReader};
use std::net::{TcpStream, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
               ToSocketAddrs};

pub use v4::{Socks4Stream, Socks4Listener};

mod v4;

/// A description of a connection target.
#[derive(Debug, Clone)]
pub enum TargetAddr {
    /// Connect to an IP address.
    Ip(SocketAddr),
    /// Connect to a fully qualified domain name.
    ///
    /// The domain name will be passed along to the proxy server and DNS lookup
    /// will happen there.
    Domain(String, u16),
}

/// A trait for objects that can be converted to `TargetAddr`.
pub trait ToTargetAddr {
    /// Converts the value of `self` to a a `TargetAddr`.
    fn to_target_addr(&self) -> io::Result<TargetAddr>;
}

impl ToTargetAddr for TargetAddr {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        Ok(self.clone())
    }
}

impl ToTargetAddr for SocketAddr {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        Ok(TargetAddr::Ip(*self))
    }
}

impl ToTargetAddr for SocketAddrV4 {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddr::V4(*self).to_target_addr()
    }
}

impl ToTargetAddr for SocketAddrV6 {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddr::V6(*self).to_target_addr()
    }
}

impl ToTargetAddr for (Ipv4Addr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddrV4::new(self.0, self.1).to_target_addr()
    }
}

impl ToTargetAddr for (Ipv6Addr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddrV6::new(self.0, self.1, 0, 0).to_target_addr()
    }
}

impl<'a> ToTargetAddr for (&'a str, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        // try to parse as an IP first
        if let Ok(addr) = self.0.parse::<Ipv4Addr>() {
            return (addr, self.1).to_target_addr();
        }

        if let Ok(addr) = self.0.parse::<Ipv6Addr>() {
            return (addr, self.1).to_target_addr();
        }

        Ok(TargetAddr::Domain(self.0.to_owned(), self.1))
    }
}

impl<'a> ToTargetAddr for &'a str {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        // try to parse as an IP first
        if let Ok(addr) = self.parse::<SocketAddrV4>() {
            return addr.to_target_addr();
        }

        if let Ok(addr) = self.parse::<SocketAddrV6>() {
            return addr.to_target_addr();
        }

        // split the string by ':' and convert the second part to u16
        let mut parts_iter = self.rsplitn(2, ':');
        let port_str = match parts_iter.next() {
            Some(s) => s,
            None => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid socket address"))
            }
        };

        let host = match parts_iter.next() {
            Some(s) => s,
            None => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid socket address"))
            }
        };

        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid port value")),
        };

        (host, port).to_target_addr()
    }
}

/// A SOCKS5 client.
#[derive(Debug)]
pub struct Socks5Stream {
    socket: TcpStream,
    proxy_addr: SocketAddr,
}

impl Socks5Stream {
    /// Connects to a target server through a SOCKS5 proxy.
    pub fn connect<T, U>(proxy: T, target: U) -> io::Result<Socks5Stream>
        where T: ToSocketAddrs,
              U: ToTargetAddr
    {
        let mut socket = BufReader::with_capacity(263, try!(TcpStream::connect(proxy)));

        let target = try!(target.to_target_addr());

        let mut packet = vec![];
        let _ = packet.write_u8(5); // protocol version
        let _ = packet.write_u8(1); // method count
        let _ = packet.write_u8(0); // no authentication
        try!(socket.get_mut().write_all(&packet));

        if try!(socket.read_u8()) != 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        match try!(socket.read_u8()) {
            0 => {}
            0xff => return Err(io::Error::new(io::ErrorKind::Other, "no acceptable auth methods")),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown auth method")),
        }

        packet.clear();
        let _ = packet.write_u8(5); // protocol version
        let _ = packet.write_u8(1); // command
        let _ = packet.write_u8(0); // reserved
        match target {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                let _ = packet.write_u8(1);
                let _ = packet.write_u32::<BigEndian>((*addr.ip()).into());
                let _ = packet.write_u16::<BigEndian>(addr.port());
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                let _ = packet.write_u8(4);
                for &part in &addr.ip().segments()[..] {
                    let _ = packet.write_u16::<BigEndian>(part);
                }
                let _ = packet.write_u16::<BigEndian>(addr.port());
            }
            TargetAddr::Domain(ref domain, port) => {
                let _ = packet.write_u8(3);
                if domain.len() > u8::max_value() as usize {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "domain name too long"));
                }
                let _ = packet.write_u8(domain.len() as u8);
                let _ = packet.write_all(domain.as_bytes());
                let _ = packet.write_u16::<BigEndian>(port);
            }
        }
        try!(socket.get_mut().write_all(&packet));

        if try!(socket.read_u8()) != 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        match try!(socket.read_u8()) {
            0 => {}
            1 => return Err(io::Error::new(io::ErrorKind::Other, "general SOCKS server failure")),
            2 => {
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "connection not allowed by ruleset"))
            }
            3 => return Err(io::Error::new(io::ErrorKind::Other, "network unreachable")),
            4 => return Err(io::Error::new(io::ErrorKind::Other, "host unreachable")),
            5 => return Err(io::Error::new(io::ErrorKind::Other, "connection refused")),
            6 => return Err(io::Error::new(io::ErrorKind::Other, "TTL expired")),
            7 => return Err(io::Error::new(io::ErrorKind::Other, "command not supported")),
            8 => return Err(io::Error::new(io::ErrorKind::Other, "address kind not supported")),
            _ => return Err(io::Error::new(io::ErrorKind::Other, "unknown error")),
        }

        if try!(socket.read_u8()) != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid reserved byte"));
        }

        let proxy_addr = match try!(socket.read_u8()) {
            1 => {
                let ip = Ipv4Addr::from(try!(socket.read_u32::<BigEndian>()));
                let port = try!(socket.read_u16::<BigEndian>());
                SocketAddr::V4(SocketAddrV4::new(ip, port))
            }
            4 => {
                let ip = Ipv6Addr::new(try!(socket.read_u16::<BigEndian>()),
                                       try!(socket.read_u16::<BigEndian>()),
                                       try!(socket.read_u16::<BigEndian>()),
                                       try!(socket.read_u16::<BigEndian>()),
                                       try!(socket.read_u16::<BigEndian>()),
                                       try!(socket.read_u16::<BigEndian>()),
                                       try!(socket.read_u16::<BigEndian>()),
                                       try!(socket.read_u16::<BigEndian>()));
                let port = try!(socket.read_u16::<BigEndian>());
                SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
            }
            _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupported address type")),
        };

        Ok(Socks5Stream {
            socket: socket.into_inner(),
            proxy_addr: proxy_addr,
        })
    }

    /// Returns the proxy-side address of the connection between the proxy and
    /// target server.
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    /// Returns a shared reference to the inner `TcpStream`.
    pub fn get_ref(&self) -> &TcpStream {
        &self.socket
    }

    /// Returns a mutable reference to the inner `TcpStream`.
    pub fn get_mut(&mut self) -> &mut TcpStream {
        &mut self.socket
    }

    /// Consumes the `Socks4Stream`, returning the inner `TcpStream`.
    pub fn into_inner(self) -> TcpStream {
        self.socket
    }
}

impl Read for Socks5Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.read(buf)
    }
}

impl<'a> Read for &'a Socks5Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.socket).read(buf)
    }
}

impl Write for Socks5Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

impl<'a> Write for &'a Socks5Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.socket).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.socket).flush()
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, TcpStream};

    use super::*;

    fn google_ip() -> SocketAddrV4 {
        "google.com:80"
            .to_socket_addrs()
            .unwrap()
            .filter_map(|a| {
                match a {
                    SocketAddr::V4(a) => Some(a),
                    SocketAddr::V6(_) => None,
                }
            })
            .next()
            .unwrap()
    }

    #[test]
    fn google_v4() {
        let mut socket = Socks4Stream::connect("127.0.0.1:1080", google_ip(), "").unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        println!("{}", String::from_utf8_lossy(&result));
        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
    }

    #[test]
    fn google_dns_v4() {
        // dante doesn't support SOCKS4A
        let mut socket = Socks4Stream::connect("127.0.0.1:8080", "google.com:80", "").unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        println!("{}", String::from_utf8_lossy(&result));
        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
    }

    #[test]
    fn google_v5() {
        let mut socket = Socks4Stream::connect("127.0.0.1:1080", google_ip(), "").unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        println!("{}", String::from_utf8_lossy(&result));
        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
    }

    #[test]
    fn google_dns_v5() {
        let mut socket = Socks5Stream::connect("127.0.0.1:1080", "google.com:80").unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        println!("{}", String::from_utf8_lossy(&result));
        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
    }

    #[test]
    fn bind() {
        // First figure out our local address that we'll be connecting from
        let socket = Socks4Stream::connect("127.0.0.1:1080", google_ip(), "").unwrap();
        let addr = socket.proxy_addr();

        let listener = Socks4Listener::bind("127.0.0.1:1080", addr, "").unwrap();
        let addr = listener.proxy_addr().unwrap();
        let mut end = TcpStream::connect(addr).unwrap();
        let mut conn = listener.accept().unwrap();
        conn.write_all(b"hello world");
        drop(conn);
        let mut result = vec![];
        end.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"hello world");
    }
}
