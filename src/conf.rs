/*!
An INI parser for files containing the general OFFWall configuration.

The files have to have the following structure.
The `[Connection]` and `[Table]` sections can be left out and have a default.

```ini
[Connection]
uri=tcp:192.0.2.1:6633

; A TLS connection setup:
; uri=tls:192.0.2.1:6633
; pkcs12=/etc/offwall.p12
; passwd=s3cr3t

[Table]
id=0

[Networks]
inside=192.0.2.0/28

[Ports]
inside=1
fw_in=2
fw_out=3
outside=4
```
*/

use bypass_csv::Direction;
use openflow::messages::OFPP_MAX;

use ini::Ini;
use ini::ini;

use ipnetwork::{IpNetworkError, Ipv4Network};

use std::convert::From;
use std::default::Default;
use std::error;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
use std::iter::IntoIterator;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::ParseIntError;
use std::str::FromStr;
use std::vec;

use tls_api;
use tls_api::TlsAcceptorBuilder;

#[cfg(feature = "tls")]
use tls_api_openssl;

const PORTS_SECTION: &str = "Ports";
const INSIDE_KEY: &str = "inside";
const FW_IN_KEY: &str = "fw_in";
const FW_OUT_KEY: &str = "fw_out";
const OUTSIDE_KEY: &str = "outside";

const CONN_SECTION: &str = "Connection";
const URI_KEY: &str = "uri";
const P12_KEY: &str = "pkcs12";
const PASS_KEY: &str = "passwd";

/// Official IANA registered port for OpenFlow.
const OFP_TCP_PORT: u16 = 6653;

const NET_SECTION: &str = "Networks";

const TABLE_SECTION: &str = "Table";
const ID_KEY: &str = "id";

/// Represents all errors that can occur
/// while parsing an INI configuration file
#[derive(Debug)]
pub enum Error {
    /// An I/O error
    Io(io::Error),
    /// A general parsing error from the INI parsing library
    Ini(ini::Error),
    /// An error while parsing the OpenFlow Table ID
    ParseTableId(ParseIntError),
    /// An error while parsing a switch port number
    ParseSwitchPort(ParseIntError),
    /// The successfully parsed number is not in the allowed range
    InvalidSwitchPortNo(String),
    /// An error while parsing an IP address in CIDR representation
    InvalidCidr(IpNetworkError, String),
    /// A required INI section is missing
    MissingSection(&'static str),
    /// A required key is missing from an available INI section
    MissingEntry(&'static str, &'static str),
    /// An invalid OpenFlow Connection URI
    InvalidUri,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "{}", e),
            Error::Ini(ref e) => write!(f, "{}", e),
            Error::ParseTableId(ref e) => {
                write!(f, "Error on trying to parse the OpenFlow Table ID: {}", e)
            }
            Error::ParseSwitchPort(ref e) => {
                write!(f, "Error on trying to parse a switch port number: {}", e)
            }
            Error::InvalidSwitchPortNo(ref p) => write!(f, "Switch port number {} is invalid", p),
            Error::InvalidCidr(ref e, ref s) => {
                write!(f, "Error on trying to parse '{}' as IP CIDR: {}", s, e)
            }
            Error::MissingSection(s) => write!(f, "The INI file does not have a [{}] section", s),
            Error::MissingEntry(s, k) => {
                write!(f, "The INI [{}] section does not have a '{}' key", s, k)
            }
            Error::InvalidUri => write!(f, "The OpenFlow Connection URI is invalid"),
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(ioe) => ioe,
            _ => io::Error::new(io::ErrorKind::InvalidData, e),
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::ParseSwitchPort(e)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "INI configuration parser error"
    }
}

/// A physical or logical OpenFlow Port
#[derive(Debug)]
pub struct OfPort {
    /// The OpenFlow Port number
    of_port: u32,
}
impl OfPort {
    /// Gets the OpenFlow Port number
    pub fn of_port(&self) -> u32 {
        self.of_port
    }
}

/// The ports of a switch that are
/// subject to the firewall bypassing
#[derive(Debug)]
pub struct OfPorts {
    inside: OfPort,
    fw_in: OfPort,
    fw_out: OfPort,
    outside: OfPort,
}

/// An OpenFlow Table that is the target for
/// all of OFFWall's flow mod messages
#[derive(Debug)]
pub struct OfTable {
    /// The target OpenFlow Table's ID
    id: u8,
}
impl OfTable {
    /// Gets the target OpenFlow Table's ID
    pub fn id(&self) -> u8 {
        self.id
    }
}

/// The Protocol that is used to connect
/// OFFWall to OpenFlow Switches
#[derive(Debug, PartialEq)]
enum ConnectionProtocol {
    Tcp,
    #[cfg(feature = "tls")]
    Tls,
}
impl FromStr for ConnectionProtocol {
    type Err = Error;

    fn from_str(proto: &str) -> Result<ConnectionProtocol, Self::Err> {
        match proto {
            "tcp" => Ok(ConnectionProtocol::Tcp),
            #[cfg(feature = "tls")]
            "tls" => Ok(ConnectionProtocol::Tls),
            _ => Err(Error::InvalidUri),
        }
    }
}

/// Each struct that represents one [Section] of
/// the INI file has to implement the Section trait
trait Section<S> {
    /// Reads one INI section and converts it to the assigned data type
    fn from_ini(conf: &Ini) -> Result<S, Error>;
}

/// Contains the parsed information from an OpenFlow Connection URI and the
/// PKCS#12 information to act as an OpenFlow Controller and possibly TLS server
#[derive(Debug)]
pub struct OfConnection {
    proto: ConnectionProtocol,
    socket: SocketAddr,
    /// None for TCP connections, Some((bytes, password)) for TLS connections.
    /// bytes contains a PKCS #12 archive with private key + certificate chain.
    pkcs12: Option<(Vec<u8>, String)>,
}
impl OfConnection {
    /// Gets the SocketAddr that is utilized
    /// to serve OpenFlow Connections
    pub fn socket(&self) -> SocketAddr {
        self.socket
    }

    /// Builds a TLS endpoint that is utilized to serve secure OpenFlow Connections.
    /// None if the OfConnection is plain TCP.
    #[cfg(feature = "tls")]
    pub fn tls_acceptor(&self) -> tls_api::Result<Option<tls_api_openssl::TlsAcceptor>> {
        Ok(match self.pkcs12 {
            Some(ref p12) => {
                Some(tls_api_openssl::TlsAcceptorBuilder::from_pkcs12(&p12.0, &p12.1)?.build()?)
            }
            _ => None,
        })
    }
}
impl Section<OfConnection> for OfConnection {
    fn from_ini(conf: &Ini) -> Result<OfConnection, Error> {
        debug!("Reading [{}] section", CONN_SECTION);

        match conf.section(Some(CONN_SECTION.to_owned())) {
            Some(conn_section) => {
                let uri = conn_section
                    .get(URI_KEY)
                    .ok_or(Error::MissingEntry(CONN_SECTION, URI_KEY))?;
                let mut conn = OfConnection::from_str(uri)?;

                #[cfg(feature = "tls")]
                {
                    if conn.proto == ConnectionProtocol::Tls {
                        let path = conn_section
                            .get(P12_KEY)
                            .ok_or(Error::MissingEntry(CONN_SECTION, P12_KEY))?;
                        let mut p12 = vec![];
                        File::open(path)?.read_to_end(&mut p12)?;
                        let passwd = conn_section
                            .get(PASS_KEY)
                            .ok_or(Error::MissingEntry(CONN_SECTION, PASS_KEY))?;
                        conn.pkcs12 = Some((p12, passwd.to_owned()));
                    }
                }
                Ok(conn)
            }
            _ => Ok(OfConnection::default()),
        }
    }
}

impl FromStr for OfConnection {
    type Err = Error;

    fn from_str(conn: &str) -> Result<OfConnection, Self::Err> {
        let def_port = OFP_TCP_PORT.to_string();
        let mut conn_split: Vec<_> = conn.split(':').collect();
        if conn_split.len() == 2 {
            conn_split.push(&def_port);
        }
        if conn_split.len() == 3 {
            let joined = &format!("{}:{}", conn_split[1], conn_split[2]);
            if let Ok(socket) = SocketAddr::from_str(joined) {
                let connection = OfConnection {
                    proto: ConnectionProtocol::from_str(conn_split[0])?,
                    socket,
                    pkcs12: None,
                };
                debug!("Got {:?}", connection);
                return Ok(connection);
            }
        }
        Err(Error::InvalidUri)
    }
}

impl Default for OfConnection {
    fn default() -> Self {
        let socket_v4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), OFP_TCP_PORT);
        OfConnection {
            proto: ConnectionProtocol::Tcp,
            socket: SocketAddr::V4(socket_v4),
            pkcs12: None,
        }
    }
}

impl FromStr for OfPort {
    type Err = Error;

    fn from_str(port: &str) -> Result<OfPort, Self::Err> {
        let port_no: u32 = port.parse()?;
        if 0 == port_no || port_no > OFPP_MAX {
            return Err(Error::InvalidSwitchPortNo(port_no.to_string()));
        }

        Ok(OfPort { of_port: port_no })
    }
}

impl Section<OfPorts> for OfPorts {
    fn from_ini(conf: &Ini) -> Result<OfPorts, Error> {
        debug!("Reading [{}] section", PORTS_SECTION);

        let ports_section = conf.section(Some(PORTS_SECTION.to_owned()))
            .ok_or(Error::MissingSection(PORTS_SECTION))?;

        let inside = ports_section
            .get(INSIDE_KEY)
            .ok_or(Error::MissingEntry(PORTS_SECTION, INSIDE_KEY))?;
        let fw_in = ports_section
            .get(FW_IN_KEY)
            .ok_or(Error::MissingEntry(PORTS_SECTION, FW_IN_KEY))?;
        let fw_out = ports_section
            .get(FW_OUT_KEY)
            .ok_or(Error::MissingEntry(PORTS_SECTION, FW_OUT_KEY))?;
        let outside = ports_section
            .get(OUTSIDE_KEY)
            .ok_or(Error::MissingEntry(PORTS_SECTION, OUTSIDE_KEY))?;

        // the port values are trimmed, so try to parse directly
        let ports = OfPorts {
            inside: OfPort::from_str(inside)?,
            fw_in: OfPort::from_str(fw_in)?,
            fw_out: OfPort::from_str(fw_out)?,
            outside: OfPort::from_str(outside)?,
        };

        debug!("Got {:?}", ports);
        Ok(ports)
    }
}

impl OfPorts {
    /// Gets the OpenFlow port that is considered to
    /// be at the OpenFlow Switch's inside network
    pub fn inside(&self) -> &OfPort {
        &self.inside
    }
    /// Gets the OpenFlow port that is considered to
    /// be at the OpenFlow Switch's connection to the
    /// firewall that is responsible for the data flow
    /// from and to the inside network
    pub fn fw_in(&self) -> &OfPort {
        &self.fw_in
    }
    /// Gets the OpenFlow port that is considered to
    /// be at the OpenFlow Switch's connection to the
    /// firewall that is responsible for the data flow
    /// from and to the outside network
    pub fn fw_out(&self) -> &OfPort {
        &self.fw_out
    }
    /// Gets the OpenFlow port that is considered to
    /// be at the OpenFlow Switch's outside network
    pub fn outside(&self) -> &OfPort {
        &self.outside
    }

    /// Returns the tuple (input port, output port) for a firewall
    /// bypass rule depending on the `Direction` of a `BypassRecord`
    pub fn in_out_from_direction(&self, dir: Direction) -> (&OfPort, &OfPort) {
        match dir {
            Direction::Inside => (&self.outside, &self.inside),
            Direction::Outside => (&self.inside, &self.outside),
        }
    }
}

impl<'a> IntoIterator for &'a OfPorts {
    type Item = &'a OfPort;
    type IntoIter = vec::IntoIter<&'a OfPort>;

    fn into_iter(self) -> Self::IntoIter {
        let v = vec![&self.inside, &self.fw_in, &self.fw_out, &self.outside];
        v.into_iter()
    }
}

impl Section<Ipv4Network> for Ipv4Network {
    fn from_ini(conf: &Ini) -> Result<Ipv4Network, Error> {
        debug!("Reading [{}] section", NET_SECTION);

        let net_section = conf.section(Some(NET_SECTION.to_owned()))
            .ok_or(Error::MissingSection(NET_SECTION))?;

        let inside = net_section
            .get(INSIDE_KEY)
            .ok_or(Error::MissingEntry(NET_SECTION, INSIDE_KEY))?;

        let net =
            Ipv4Network::from_str(inside).map_err(|e| Error::InvalidCidr(e, inside.to_string()))?;

        debug!("Got {:?}", net);
        Ok(net)
    }
}

impl Section<OfTable> for OfTable {
    fn from_ini(conf: &Ini) -> Result<OfTable, Error> {
        debug!("Reading [{}] section", TABLE_SECTION);

        let table = match conf.section(Some(TABLE_SECTION.to_owned())) {
            Some(table_section) => {
                let id = table_section
                    .get(ID_KEY)
                    .ok_or(Error::MissingEntry(TABLE_SECTION, ID_KEY))?;

                Ok(OfTable {
                    id: id.parse().map_err(Error::ParseTableId)?,
                })
            }

            _ => Ok(OfTable::default()),
        };

        debug!("Got {:?}", table);
        table
    }
}

impl Default for OfTable {
    fn default() -> Self {
        OfTable { id: 0 }
    }
}

/// Parses an INI file at `path` that is expected to contain the OFFWall
/// configuration structure and returns a tuple of the configuration aspects
pub fn parse_file(path: &str) -> Result<(OfConnection, OfTable, OfPorts, Ipv4Network), Error> {
    info!("Reading INI file {}", path);

    let conf = match Ini::load_from_file(path) {
        Ok(i) => i,
        Err(e) => {
            return Err(Error::Ini(e));
        }
    };

    Ok((
        OfConnection::from_ini(&conf)?,
        OfTable::from_ini(&conf)?,
        OfPorts::from_ini(&conf)?,
        Ipv4Network::from_ini(&conf)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_tcp() {
        let testee = ConnectionProtocol::from_str("tcp").unwrap();
        assert_eq!(ConnectionProtocol::Tcp, testee);
    }

    #[test]
    fn wrong_proto() {
        OfConnection::from_str("fail").unwrap_err();
    }
}
