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

use notify;
use notify::{DebouncedEvent, RecursiveMode, Watcher};

use std::collections::HashSet;
use std::convert::From;
use std::error;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

/// The polling frequency
const NOTIFY_SECONDS: u64 = 1;

/// The CSV delimiter.
const DELIMITER: char = ';';

/// The char introducing a line comment.
const COMMENT: char = '#';

/// Represents all errors that can occur while
/// parsing a CSV file with firewall bypass rules
#[derive(Debug, PartialEq)]
pub enum Error {
    /// A line does not have exactly 5 values
    ValueCount(String),
    /// A line does have an empty value
    EmptyValue(String),
    /// An invalid CIDR form occured
    InvalidCidr(IpNetworkError, String),
    /// A UDP or TCP number is invalid
    InvalidPortNumber(String),
    /// An IP protocol is referenced that is not supported
    InvalidProtocol(String),
    /// A line only contains wildcards
    OnlyWildcards(String),
    /// A line contains at least one port
    /// number with protocol being a wildcard
    PortWithProtocolWildcard(String),
    /// A line contains at least one port number with ICMP
    PortWithIcmp(String),
    /// A line does not contain an IP range
    /// that is in the configured inside net
    NotMatchingInsideNet(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ValueCount(ref s) => {
                write!(f, "The following line does not have exactly 5 values: {}", s)
            }
            Error::EmptyValue(ref s) => {
                write!(f, "The following line has an empty value: {}", s)
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

/// The direction of a data flow (either going to
/// the inside or going to the outside network)
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub enum Direction {
    /// The data goes to the inside network
    Inside,
    /// The data goes to the outside network
    Outside,
}

/// Each of the IP protocols that a firewall bypass rule can contain
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub enum IpProtocol {
    /// Internet Control Message Protocol
    Icmp = 1,
    /// Transmission Control Protocol
    Tcp = 6,
    /// User Datagram Protocol
    Udp = 17,
}

/// Represents one record of the bypass rules.
/// A member wildcard is represented as None value.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct BypassRecord {
    /// The source IP address
    src_ip: Option<Ipv4Network>,
    /// The source port
    src_port: Option<u16>,
    /// The destination IP address
    dst_ip: Option<Ipv4Network>,
    /// The destination port
    dst_port: Option<u16>,
    /// The IP protocol
    proto: Option<IpProtocol>,
    /// The direction. The switch's input/output
    /// ports should be derived from it.
    direction: Direction,
}

impl BypassRecord {
    /// Gets the source IP address
    pub fn src_ip(&self) -> Option<Ipv4Network> {
        self.src_ip
    }
    /// Gets the source port
    pub fn src_port(&self) -> Option<u16> {
        self.src_port
    }
    /// Gets the destination IP address
    pub fn dst_ip(&self) -> Option<Ipv4Network> {
        self.dst_ip
    }
    /// Gets the destination port
    pub fn dst_port(&self) -> Option<u16> {
        self.dst_port
    }
    /// Gets the IP protocol
    pub fn proto(&self) -> Option<IpProtocol> {
        self.proto
    }
    /// Gets the direction
    pub fn direction(&self) -> Direction {
        self.direction
    }

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

/// The line oriented parser for CSV firewall bypass rules
pub struct CsvParser {
    path: String,
    inside_net: Ipv4Network,
}

impl CsvParser {
    /// Gets the path of the file that this parser operates on
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Constructs a new `CsvParser`
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
    fn parse_line(&self, line: &str) -> Result<Vec<BypassRecord>, Error> {
        if line.is_empty() || line.starts_with(COMMENT) {
            return Ok(Vec::with_capacity(0));
        }

        let mut csv_elems = vec![];
        for item in line.split(DELIMITER) {
            let trimmed = match item.trim() {
                // check wildcard
                "*" => None,
                "" => return Err(Error::EmptyValue(line.to_string())),
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
            let records = self.parse_line(&line)?;
            for rec in records {
                bypass_records.insert(rec);
            }
        }

        Ok(bypass_records)
    }

    /// Registers a file as notify target.
    /// If the registering fails, the file is tried to be reregistered infinitely.
    pub fn watch_file(&self, record_tx: &Sender<HashSet<BypassRecord>>) {
        loop {
            let (tx, rx) = mpsc::channel();
            if let Ok(mut watcher) = notify::watcher(tx, Duration::from_secs(NOTIFY_SECONDS)) {
                if watcher
                    .watch(&self.path(), RecursiveMode::NonRecursive)
                    .is_ok()
                {
                    info!("Watching file {}", self.path());
                    match self.handle_file_events(&rx, record_tx) {
                        Ok(_) => warn!("file watch removed"),
                        Err(e) => error!("{}", e),
                    }
                }
            }
        }
    }

    /// Reads inode events and parses the corresponding file.
    /// If the inode is removed, it is unregistered from notify.
    fn handle_file_events(
        &self,
        rx: &Receiver<DebouncedEvent>,
        tx: &Sender<HashSet<BypassRecord>>,
    ) -> notify::Result<()> {
        loop {
            match rx.recv().expect("inter-thread communication failed") {
                DebouncedEvent::NoticeRemove(_) | DebouncedEvent::Remove(_) => {
                    return Ok(());
                }
                DebouncedEvent::Error(error, _) => {
                    return Err(error);
                }
                _ => match self.parse_file() {
                    Ok(recs) => tx.send(recs).expect("inter-thread communication failed"),
                    Err(io_err) => {
                        return Err(notify::Error::Io(io_err));
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_parser() -> CsvParser {
        CsvParser::new(
            "".to_string(),
            Ipv4Network::from_str("192.0.2.0/24").unwrap(),
        )
    }

    #[test]
    fn wrong_value_count() {
        let testee = test_parser().parse_line("a");
        assert_eq!(Error::ValueCount("a".to_string()), testee.unwrap_err());
    }

    #[test]
    fn empty_value() {
        let testee = test_parser().parse_line("a;b;c;d;");
        let expected = Error::EmptyValue("a;b;c;d;".to_string());
        assert_eq!(expected, testee.unwrap_err());
    }

    #[test]
    fn invaid_cidr() {
        let line = "192.0.2.0/50;*;*;*;*";
        let testee = test_parser().parse_line(line);
        let expected = Error::InvalidCidr(IpNetworkError::InvalidPrefix, line.to_string());
        assert_eq!(expected, testee.unwrap_err());
    }

    #[test]
    fn port_too_big() {
        let testee = test_parser().parse_line("*;70000;*;*;TCP");
        let expected = Error::InvalidPortNumber("70000".to_string());
        assert_eq!(expected, testee.unwrap_err());
    }

    #[test]
    fn port_too_small() {
        let testee = test_parser().parse_line("*;-1;*;*;TCP");
        let expected = Error::InvalidPortNumber("-1".to_string());
        assert_eq!(expected, testee.unwrap_err());
    }

    #[test]
    fn invalid_protocol() {
        let testee = test_parser().parse_line("*;*;*;*;fail");
        let expected = Error::InvalidProtocol("fail".to_string());
        assert_eq!(expected, testee.unwrap_err());
    }

    #[test]
    fn comment() {
        let testee = test_parser().parse_line("# comment");
        assert!(testee.unwrap().is_empty());
    }

    #[test]
    fn empty() {
        let testee = test_parser().parse_line("");
        assert!(testee.unwrap().is_empty());
    }

}
