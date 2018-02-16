/*!
A CSV parser for files with firewall bypass rules.

# Syntax

The CSV is separated by semicolons.
Empty lines and lines beginning with `#` are ignored.
You can place a `*` if you want to express a wildcard.
A record consisting only of wildcards is not allowed.
Whitespaces surrounding the values are ignored.

Each line consists of a 5-tupel describing a connection
that is to bypass, e.g.

```csv
# src_cidr  ;src_port;dst_cidr     ;dst_port;proto
192.0.2.0/24;*       ;192.0.2.10/32;80      ;TCP
```

You have to use IPv4 CIDR suffix notation.
The IP Protocol (proto) value can be TCP, UDP or `*`.
If it is `*`, the port numbers also have to be `*`.
*/

use ipnetwork::{IpNetworkError, Ipv4Network};

use std::collections::HashSet;
use std::convert::From;
use std::error;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::str::FromStr;

/// The CSV delimiter.
const DELIMITER: char = ';';

/// The char introducing a line comment.
const COMMENT: char = '#';

#[derive(Debug)]
pub enum Error {
    ValueCount(String),
    InvalidCidr(IpNetworkError, String),
    InvalidPortNumber(String),
    InvalidProtocol(String),
    OnlyWildcards(String),
    PortWithProtocolWildcard(String),
    PortWithIcmp(String),
    NotMatchingInsideNet(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ValueCount(ref s) => {
                write!(f, "The following line does not have exactly 5 values: {}", s)
            }
            Error::InvalidCidr(ref e, ref s) => {
                write!(f, "{} -- Violating line: {}", e, s)
            }
            Error::InvalidPortNumber(ref p) => {
                write!(f, "{} is an invalid port number.", p)
            }
            Error::InvalidProtocol(ref p) => {
                write!(f, "{} is an invalid protocol.", p)
            }
            Error::OnlyWildcards(ref s) => {
                write!(f, "The following line only contains wildcards, which would overwrite default rules: {}", s)
            }
            Error::PortWithProtocolWildcard(ref s) => {
                write!(f, "The following line contains at least one port number with protocol being a wildcard: {}", s)
            }
            Error::PortWithIcmp(ref s) => {
                write!(f, "The following line contains at least one port number with ICMP: {}", s)
            }
            Error::NotMatchingInsideNet(ref s) => {
                write!(f, "The following line does not contain an IP range that is in the configured inside net: {}", s)
            }
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "bypass_csv parser error"
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub enum Direction {
    Inside,
    Outside,
}

/// The IP protocols that are allowed.
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

/// Represents one record of the bypass rules.
/// A member wildcard is represented as None value.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct BypassRecord {
    /// The source IP address
    pub src_ip: Option<Ipv4Network>,
    /// The source port
    pub src_port: Option<u16>,
    /// The destination IP address
    pub dst_ip: Option<Ipv4Network>,
    /// The destination port
    pub dst_port: Option<u16>,
    /// The IP protocol
    pub proto: Option<IpProtocol>,
    /// The direction. The switch's input/output ports should be derived from it.
    pub direction: Direction,
}

impl BypassRecord {
    fn reverse_direction(&self) -> BypassRecord {
        let direction = match self.direction {
            Direction::Inside => Direction::Outside,
            Direction::Outside => Direction::Inside,
        };
        BypassRecord {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
            proto: self.proto,
            direction: direction,
        }
    }
}

fn parse_port_number(ps: &str) -> Result<u16, Error> {
    ps.parse()
        .map_err(|_| Error::InvalidPortNumber(ps.to_string()))
}

fn parse_protocol(ps: &str) -> Result<IpProtocol, Error> {
    match ps {
        "ICMP" | "icmp" => Ok(IpProtocol::Icmp),
        "UDP" | "udp" => Ok(IpProtocol::Udp),
        "TCP" | "tcp" => Ok(IpProtocol::Tcp),
        _ => Err(Error::InvalidProtocol(ps.to_string())),
    }
}

pub struct CsvParser {
    pub path: String,
    inside_net: Ipv4Network,
}

impl CsvParser {
    pub fn new(path: String, inside_net: Ipv4Network) -> CsvParser {
        CsvParser {
            path: path,
            inside_net: inside_net,
        }
    }

    /// Checks for `ip_net` to be in `self.inside_net`
    fn in_inside_net(&self, ip_net: Option<Ipv4Network>) -> bool {
        ip_net.map_or(false, |ip| self.inside_net.contains(ip.network()))
    }

    /// Parses one CSV line and validates it semantically.
    /// src_ip or dst_ip has to be in `inside_net`.
    /// Dependent on this the output_port is set.
    /// The corresponding `BypassRecord` and its reverse are returned.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = parse_line("# comment");
    /// assert_eq!(Ok(None));
    /// ```
    fn parse_line(&self, line: String) -> Result<Vec<BypassRecord>, Error> {
        if line.is_empty() || line.starts_with(COMMENT) {
            return Ok(Vec::with_capacity(0));
        }

        let mut csv_elems = vec![];
        for item in line.split(DELIMITER) {
            let trimmed = match item.trim() {
                // check wildcard
                "*" => None,
                trm => Some(trm),
            };
            csv_elems.push(trimmed);
        }

        // check 5-tupel
        if csv_elems.len() != 5 {
            return Err(Error::ValueCount(line.to_string()));
        }

        let src_port = match csv_elems[1] {
            Some(p) => Some(parse_port_number(p)?),
            _ => None,
        };
        let dst_port = match csv_elems[3] {
            Some(p) => Some(parse_port_number(p)?),
            _ => None,
        };

        let src_ip = match csv_elems[0] {
            Some(ip) => {
                let invalid_cidr = |e| Error::InvalidCidr(e, line.to_string());
                Some(Ipv4Network::from_str(ip).map_err(invalid_cidr)?)
            }
            _ => None,
        };
        let dst_ip = match csv_elems[2] {
            Some(ip) => {
                let invalid_cidr = |e| Error::InvalidCidr(e, line.to_string());
                Some(Ipv4Network::from_str(ip).map_err(invalid_cidr)?)
            }
            _ => None,
        };

        let proto = match csv_elems[4] {
            Some(proto) => Some(parse_protocol(proto)?),
            _ => None,
        };

        // check for semantic errors
        if src_ip == None && src_port == None && dst_ip == None && dst_port == None && proto == None
        {
            return Err(Error::OnlyWildcards(line.to_string()));
        }
        if (src_port != None || dst_port != None) && proto == None {
            return Err(Error::PortWithProtocolWildcard(line.to_string()));
        }
        if (src_port != None || dst_port != None) && proto == Some(IpProtocol::Icmp) {
            return Err(Error::PortWithIcmp(line.to_string()));
        }
        let direction = if self.in_inside_net(src_ip) {
            Direction::Outside
        }
        else if self.in_inside_net(dst_ip) {
            Direction::Inside
        }
        else {
            return Err(Error::NotMatchingInsideNet(line.to_string()));
        };

        let rec = BypassRecord {
            src_ip: src_ip,
            src_port: src_port,
            dst_ip: dst_ip,
            dst_port: dst_port,
            proto: proto,
            direction: direction,
        };
        let rec_reverse = rec.reverse_direction();

        debug!("Got {:?}", rec);
        debug!("Got {:?}", rec_reverse);

        Ok(vec![rec, rec_reverse])
    }

    /// Parses a CSV file and returns its records
    pub fn parse_file(&self) -> io::Result<HashSet<BypassRecord>> {
        info!("Reading CSV file {}", self.path);

        let file = File::open(&self.path).map_err(|e| {
            io::Error::new(e.kind(), format!("Unable to open `{:?}`: {}", self.path, e))
        })?;
        let reader = io::BufReader::new(file);

        let mut bypass_records = HashSet::new();

        for line_res in reader.lines() {
            let line = line_res?;
            let records = self.parse_line(line)?;
            for rec in records {
                bypass_records.insert(rec);
            }
        }

        Ok(bypass_records)
    }
}
