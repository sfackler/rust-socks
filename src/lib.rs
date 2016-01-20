extern crate byteorder;

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::io::{self, Read, Write};
use std::net::{TcpStream, Ipv4Addr, SocketAddrV4, ToSocketAddrs};

pub struct Socks4Socket {
    socket: TcpStream,
    addr: SocketAddrV4,
}

impl Socks4Socket {
    pub fn connect<T>(proxy: T, target: Ipv4Addr, port: u16) -> io::Result<Socks4Socket>
        where T: ToSocketAddrs
    {
        let mut socket = try!(TcpStream::connect(proxy));

        let mut packet = vec![];
        let _ = packet.write_u8(4); // version
        let _ = packet.write_u8(1); // command code
        let _ = packet.write_u16::<BigEndian>(port); // port
        let _ = packet.write_u32::<BigEndian>(target.into()); // ip
        let _ = packet.write_u8(0); // empty user id

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
        let mut socket = Socks4Socket::connect("127.0.0.1:8080",
                                               "216.58.192.46".parse().unwrap(),
                                               80).unwrap();

        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut result = vec![];
        socket.read_to_end(&mut result).unwrap();

        assert!(result.starts_with(b"HTTP/1.0 200 OK"));
        assert!(result.ends_with(b"</html>"));
    }
}
