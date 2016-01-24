use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::io::{self, Read, Write, BufReader};
use std::net::{SocketAddr, ToSocketAddrs, SocketAddrV4, SocketAddrV6, TcpStream, Ipv4Addr,
               Ipv6Addr};

use {ToTargetAddr, TargetAddr};

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
    use std::net::ToSocketAddrs;

    use super::*;

    #[test]
    fn google() {
        let addr = "google.com:80".to_socket_addrs().unwrap().next().unwrap();
        let mut socket = Socks5Stream::connect("127.0.0.1:1080", addr).unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        println!("{}", String::from_utf8_lossy(&result));
        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
    }

    #[test]
    fn google_dns() {
        let mut socket = Socks5Stream::connect("127.0.0.1:1080", "google.com:80").unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        println!("{}", String::from_utf8_lossy(&result));
        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
    }
}
