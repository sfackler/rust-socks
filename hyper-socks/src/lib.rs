//! SOCKS proxy support for Hyper clients
#![warn(missing_docs)]

extern crate socks;
extern crate hyper;

use hyper::net::{NetworkConnector, HttpStream, HttpsStream, Ssl};
use socks::Socks4Socket;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::vec;

#[derive(Debug)]
struct CachedAddrs(Vec<SocketAddr>);

impl ToSocketAddrs for CachedAddrs {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        Ok(self.0.clone().into_iter())
    }
}

/// A connector that will produce proxied HttpStreams.
#[derive(Debug)]
pub struct Socks4HttpConnector {
    addrs:  CachedAddrs,
    userid: String,
}

impl Socks4HttpConnector {
    /// Creates a new `Socks4HttpConnector` which will connect to the specified
    /// proxy with the specified userid.
    pub fn new<T: ToSocketAddrs>(proxy: T, userid: &str) -> io::Result<Socks4HttpConnector> {
        Ok(Socks4HttpConnector {
            addrs: CachedAddrs(try!(proxy.to_socket_addrs()).collect()),
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

        let socket = try!(Socks4Socket::connect(&self.addrs, (host, port), &self.userid));
        Ok(HttpStream(socket.into_inner()))
    }
}

/// A connector that will produce protected, proxied HTTP streams using SSL.
#[derive(Debug)]
pub struct Socks4HttpsConnector<S> {
    addrs: CachedAddrs,
    userid: String,
    ssl: S,
}

impl<S: Ssl> Socks4HttpsConnector<S> {
    /// Creates a new `Socks4HttpsConnector` which will connect to the specified
    /// proxy with the specified userid, and use the provided SSL implementation
    /// to encrypt the resulting stream.
    pub fn new<T: ToSocketAddrs>(proxy: T, userid: &str, ssl: S) -> io::Result<Self> {
        Ok(Socks4HttpsConnector {
            addrs: CachedAddrs(try!(proxy.to_socket_addrs()).collect()),
            userid: userid.to_owned(),
            ssl: ssl,
        })
    }
}

impl<S: Ssl> NetworkConnector for Socks4HttpsConnector<S> {
    type Stream = HttpsStream<S::Stream>;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> hyper::Result<Self::Stream> {
        if scheme != "http" && scheme != "https" {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                      "invalid scheme for HTTPS").into());
        }

        let socket = try!(Socks4Socket::connect(&self.addrs, (host, port), &self.userid));
        let stream = HttpStream(socket.into_inner());

        if scheme == "http" {
            Ok(HttpsStream::Http(stream))
        } else {
            Ok(HttpsStream::Https(try!(self.ssl.wrap_client(stream, host))))
        }
    }
}

#[cfg(test)]
mod test {
    use hyper;
    use hyper::net::Openssl;
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

    #[test]
    fn google_ssl_http() {
        let connector = Socks4HttpsConnector::new("127.0.0.1:8080", "", Openssl::default()).unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("http://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn google_ssl_https() {
        let connector = Socks4HttpsConnector::new("127.0.0.1:8080", "", Openssl::default()).unwrap();
        let client = hyper::Client::with_connector(connector);
        let mut response = client.get("https://www.google.com").send().unwrap();

        assert!(response.status.is_success());
        let mut body = vec![];
        response.read_to_end(&mut body).unwrap();
    }
}
