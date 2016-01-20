extern crate byteorder;

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::io::{self, Read, Write};
use std::net::{TcpStream, Ipv4Addr, SocketAddrV4, ToSocketAddrs};

#[derive(Clone)]
pub enum Socks4Addr {
    Ip(SocketAddrV4),
    Domain(String, u16),
}

pub trait ToSocks4Addr {
    fn to_socks4_addr(&self) -> io::Result<Socks4Addr>;
}

impl ToSocks4Addr for Socks4Addr {
    fn to_socks4_addr(&self) -> io::Result<Socks4Addr> {
        Ok(self.clone())
    }
}

impl ToSocks4Addr for SocketAddrV4 {
    fn to_socks4_addr(&self) -> io::Result<Socks4Addr> {
        Ok(Socks4Addr::Ip(*self))
    }
}

impl ToSocks4Addr for (Ipv4Addr, u16) {
    fn to_socks4_addr(&self) -> io::Result<Socks4Addr> {
        SocketAddrV4::new(self.0, self.1).to_socks4_addr()
    }
}

impl<'a> ToSocks4Addr for (&'a str, u16) {
    fn to_socks4_addr(&self) -> io::Result<Socks4Addr> {
        // try to parse as an IP first
        if let Ok(addr) = self.0.parse::<Ipv4Addr>() {
            return (addr, self.1).to_socks4_addr();
        }

        Ok(Socks4Addr::Domain(self.0.to_owned(), self.1))
    }
}

impl<'a> ToSocks4Addr for &'a str {
    fn to_socks4_addr(&self) -> io::Result<Socks4Addr> {
        // try to parse as an IP first
        if let Ok(addr) = self.parse::<SocketAddrV4>() {
            return addr.to_socks4_addr();
        }

        // split the string by ':' and convert the second part to u16
        let mut parts_iter = self.rsplitn(2, ':');
        let port_str = match parts_iter.next() {
            Some(s) => s,
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                              "invalid socket address")),
        };

        let host = match parts_iter.next() {
            Some(s) => s,
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                              "invalid socket address")),
        };

        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid port value")),
        };

        (host, port).to_socks4_addr()
    }
}

pub struct Socks4Socket {
    socket: TcpStream,
    addr: SocketAddrV4,
}

impl Socks4Socket {
    pub fn connect<T, U>(proxy: T, target: U) -> io::Result<Socks4Socket>
        where T: ToSocketAddrs,
              U: ToSocks4Addr,
    {
        let mut socket = try!(TcpStream::connect(proxy));

        let target = try!(target.to_socks4_addr());

        let mut packet = vec![];
        let _ = packet.write_u8(4); // version
        let _ = packet.write_u8(1); // command code
        match try!(target.to_socks4_addr()) {
            Socks4Addr::Ip(addr) => {
                let _ = packet.write_u16::<BigEndian>(addr.port());
                let _ = packet.write_u32::<BigEndian>((*addr.ip()).into());
                let _ = packet.write_u8(0); // empty user id
            }
            Socks4Addr::Domain(ref host, port) => {
                let _ = packet.write_u16::<BigEndian>(port);
                let _ = packet.write_u32::<BigEndian>(Ipv4Addr::new(0, 0, 0, 1).into());
                let _ = packet.write_u8(0);
                let _ = packet.extend(host.as_bytes().iter().cloned());
                let _ = packet.write_u8(0);
            }
        }

        try!(socket.write_all(&packet));

        let mut response = [0u8; 8];
        try!(socket.read_exact(&mut response));
        let mut response = &response[..];

        if try!(response.read_u8()) != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        match try!(response.read_u8()) {
            90 => {},
            91 => return Err(io::Error::new(io::ErrorKind::Other, "request rejected or failed")),
            92 => return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                                            "request rejected because SOCKS server cannot connect to \
                                             idnetd on the client")),
            93 => return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                                            "request rejected because the client program and identd \
                                             report different user-ids")),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response code"))
        }

        let port = try!(response.read_u16::<BigEndian>());
        let ip = Ipv4Addr::from(try!(response.read_u32::<BigEndian>()));

        Ok(Socks4Socket {
            socket: socket,
            addr: SocketAddrV4::new(ip, port)
        })
    }

    pub fn proxy_addr(&self) -> SocketAddrV4 {
        self.addr
    }
}

impl Read for Socks4Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.read(buf)
    }
}

impl<'a> Read for &'a Socks4Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.socket).read(buf)
    }
}

impl Write for Socks4Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

impl<'a> Write for &'a Socks4Socket {
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

    use super::*;

    #[test]
    fn google() {
        let mut socket = Socks4Socket::connect("127.0.0.1:8080", "216.58.192.46:80").unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n"));
    }

    #[test]
    fn google_dns() {
        let mut socket = Socks4Socket::connect("127.0.0.1:8080", "google.com:80").unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        assert!(result.starts_with(b"HTTP/1.0"), "{}", String::from_utf8_lossy(&result));
        assert!(result.ends_with(b"</HTML>\r\n"));
    }
}
