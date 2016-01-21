extern crate socks;
extern crate hyper;

use hyper::net::{NetworkConnector, HttpStream};
use socks::Socks4Socket;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Debug)]
pub struct Socks4HttpConnector {
    addrs:  Vec<SocketAddr>,
    userid: String,
}

impl Socks4HttpConnector {
    pub fn new<T: ToSocketAddrs>(proxy: T, userid: &str) -> io::Result<Socks4HttpConnector> {
        Ok(Socks4HttpConnector {
            addrs: try!(proxy.to_socket_addrs()).collect(),
            userid: userid.to_owned(),
        })
    }
}

impl NetworkConnector for Socks4HttpConnector {
    type Stream = HttpStream;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> hyper::Result<HttpStream> {
        if scheme != "http" {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                      "invalid scheme for HTTP").into());
        }

        let mut err = None;
        for proxy_addr in &self.addrs {
            match Socks4Socket::connect(proxy_addr, (host, port), &self.userid) {
                Ok(socket) => return Ok(HttpStream(socket.into_inner())),
                Err(e) => err = Some(e),
            } 
        }
        Err(err.unwrap().into())
    }
}

#[cfg(test)]
mod test {
    use hyper;
    use std::io::Read;

    use super::*;

    #[test]
    fn google() {
        let connector = Socks4HttpConnector::new("127.0.0.1:8080", "").unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("http://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }
}
