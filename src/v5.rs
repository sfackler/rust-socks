use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::io::{self, Read, Write, BufReader};
use std::net::{SocketAddr, ToSocketAddrs, SocketAddrV4, SocketAddrV6, TcpStream, Ipv4Addr,
               Ipv6Addr, UdpSocket};

use {ToTargetAddr, TargetAddr};

const MAX_ADDR_LEN: usize = 260;

fn read_addr<R: Read>(socket: &mut R) -> io::Result<SocketAddr> {
    match try!(socket.read_u8()) {
        1 => {
            let ip = Ipv4Addr::from(try!(socket.read_u32::<BigEndian>()));
            let port = try!(socket.read_u16::<BigEndian>());
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
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
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => Err(io::Error::new(io::ErrorKind::Other, "unsupported address type")),
    }
}

fn read_response(socket: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut socket = BufReader::with_capacity(MAX_ADDR_LEN + 3, socket);

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

    read_addr(&mut socket)
}

fn write_addr(packet: &mut Vec<u8>, target: &TargetAddr) -> io::Result<()> {
    match *target {
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

    Ok(())
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
        Self::connect_raw(1, proxy, target)
    }

    fn connect_raw<T, U>(command: u8, proxy: T, target: U) -> io::Result<Socks5Stream>
        where T: ToSocketAddrs,
              U: ToTargetAddr
    {
        let mut socket = try!(TcpStream::connect(proxy));

        let target = try!(target.to_target_addr());

        let mut packet = vec![];
        let _ = packet.write_u8(5); // protocol version
        let _ = packet.write_u8(1); // method count
        let _ = packet.write_u8(0); // no authentication
        try!(socket.write_all(&packet));

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
        let _ = packet.write_u8(command); // command
        let _ = packet.write_u8(0); // reserved
        try!(write_addr(&mut packet, &target));
        try!(socket.write_all(&packet));

        let proxy_addr = try!(read_response(&mut socket));

        Ok(Socks5Stream {
            socket: socket,
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

/// A SOCKS5 BIND client.
#[derive(Debug)]
pub struct Socks5Listener(Socks5Stream);

impl Socks5Listener {
    /// Initiates a BIND request to the specified proxy.
    ///
    /// The proxy will filter incoming connections based on the value of
    /// `target`.
    pub fn bind<T, U>(proxy: T, target: U) -> io::Result<Socks5Listener>
        where T: ToSocketAddrs,
              U: ToTargetAddr
    {
        Socks5Stream::connect_raw(2, proxy, target).map(Socks5Listener)
    }

    /// The address of the proxy-side TCP listener.
    ///
    /// This should be forwarded to the remote process, which should open a
    /// connection to it.
    pub fn proxy_addr(&self) -> SocketAddr {
        self.0.proxy_addr
    }

    /// Waits for the remote process to connect to the proxy server.
    ///
    /// The value of `proxy_addr` should be forwarded to the remote process
    /// before this method is called.
    pub fn accept(mut self) -> io::Result<Socks5Stream> {
        self.0.proxy_addr = try!(read_response(&mut self.0.socket));
        Ok(self.0)
    }
}

/// A SOCKS5 UDP client.
#[derive(Debug)]
pub struct Socks5Datagram {
    socket: UdpSocket,
    // keeps the session alive
    stream: Socks5Stream,
}

impl Socks5Datagram {
    /// Creates a UDP socket bound to the specified address which will have its
    /// traffic routed through the specified proxy.
    pub fn bind<T, U>(proxy: T, addr: U) -> io::Result<Socks5Datagram>
        where T: ToSocketAddrs,
              U: ToSocketAddrs,
    {
        // we don't know what our IP is from the perspective of the proxy, so
        // don't try to pass `addr` in here.
        let dst = TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)));
        let stream = try!(Socks5Stream::connect_raw(3, proxy, dst));

        let socket = try!(UdpSocket::bind(addr));

        Ok(Socks5Datagram {
            socket: socket,
            stream: stream
        })
    }

    /// Like `UdpSocket::send_to`.
    ///
    /// # Note
    ///
    /// The SOCKS protocol inserts a header at the beginning of the message. The
    /// header will be 10 bytes for an IPv4 address, 22 bytes for an IPv6
    /// address, and 7 bytes plus the length of the domain for a domain address.
    pub fn send_to<A>(&self, buf: &[u8], addr: A) -> io::Result<usize> where A: ToTargetAddr {
        let addr = try!(addr.to_target_addr());

        let mut packet = vec![];
        let _ = packet.write_u16::<BigEndian>(0); // reserved
        let _ = packet.write_u8(0); // fragment
        try!(write_addr(&mut packet, &addr));
        let _ = packet.write_all(buf);

        self.socket.send_to(&packet, self.stream.proxy_addr)
    }

    /// Like `UdpSocket::recv_from`.
    pub fn recv_from(&self, mut buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut inner_buf = vec![0; buf.len() + MAX_ADDR_LEN + 3];
        let len = try!(self.socket.recv_from(&mut inner_buf)).0;

        let mut inner_buf = &inner_buf[..len];
        if try!(inner_buf.read_u16::<BigEndian>()) != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid reserved bytes"));
        }
        if try!(inner_buf.read_u8()) != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid fragment id"));
        }
        let addr = try!(read_addr(&mut inner_buf));

        buf.write(inner_buf).map(|l| (l, addr))
    }

    /// Returns the address of the proxy-side UDP socket through which all
    /// messages will be routed.
    pub fn proxy_addr(&self) -> SocketAddr {
        self.stream.proxy_addr
    }

    /// Returns a shared reference to the inner socket.
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns a mutable reference to the inner socket.
    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::net::{ToSocketAddrs, TcpStream, UdpSocket};

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

    #[test]
    fn bind() {
        // First figure out our local address that we'll be connecting from
        let socket = Socks5Stream::connect("127.0.0.1:1080", "google.com:80").unwrap();
        let addr = socket.proxy_addr();

        let listener = Socks5Listener::bind("127.0.0.1:1080", addr).unwrap();
        let addr = listener.proxy_addr();
        let mut end = TcpStream::connect(addr).unwrap();
        let mut conn = listener.accept().unwrap();
        conn.write_all(b"hello world").unwrap();
        drop(conn);
        let mut result = vec![];
        end.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn associate() {
        let socks = Socks5Datagram::bind("127.0.0.1:1080", "127.0.0.1:15410").unwrap();
        let socket_addr = "127.0.0.1:15411";
        let socket = UdpSocket::bind(socket_addr).unwrap();

        socks.send_to(b"hello world!", socket_addr).unwrap();
        let mut buf = [0; 13];
        let (len, addr) = socket.recv_from(&mut buf).unwrap();
        assert_eq!(len, 12);
        assert_eq!(&buf[..12], b"hello world!");

        socket.send_to(b"hello world!", addr).unwrap();

        let len = socks.recv_from(&mut buf).unwrap().0;
        assert_eq!(len, 12);
        assert_eq!(&buf[..12], b"hello world!");
    }
}
