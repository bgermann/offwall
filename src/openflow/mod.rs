/*!
Implements an OpenFlow Controller with protocol version 0x04 compatibility.
It provides only a small subset of the OpenFlow features to push some rules
to a switch proactively.
*/

pub mod error;
pub mod messages;

use bypass_csv::BypassRecord;
use conf::*;

use openflow::error::{Error, Result};
use openflow::messages::*;
use openflow::messages::deserialize::Deserialize;
use openflow::messages::serialize::OfpPacket;

use rand;

use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::io::{Read, Write};
use std::ops::Sub;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

#[cfg(feature = "tls")]
use tls_api::TlsAcceptor;
use tls_api;
use tls_api::TlsStream;

const BASIC_FLOW_PRIORITY: u16 = 1;
const FLOW_REFRESH_SECS: u64 = 3600;

fn gen_xid() -> u32 {
    let xid = rand::random();
    trace!("Using xid {} for the outgoing message", xid);
    xid
}
#[derive(Debug)]
enum Stream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}
impl Stream {
    fn from(_connection: &OfConnection, stream: TcpStream) -> tls_api::Result<Stream> {
        #[cfg(feature = "tls")]
        {
            if let Some(acc) = _connection.tls_acceptor()? {
                return match acc.accept(stream) {
                    Ok(s) => Ok(Stream::Tls(s)),
                    Err(tls_api::HandshakeError::Failure(e)) => Err(e),
                    Err(tls_api::HandshakeError::Interrupted(_)) => {
                        Err(tls_api::Error::new_other("TLS stream was interrupted"))
                    }
                };
            }
        }
        Ok(Stream::Tcp(stream))
    }
}
impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            Stream::Tcp(ref mut s) => s.read(buf),
            Stream::Tls(ref mut s) => s.read(buf),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            Stream::Tcp(ref mut s) => s.write(buf),
            Stream::Tls(ref mut s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            Stream::Tcp(ref mut s) => s.flush(),
            Stream::Tls(ref mut s) => s.flush(),
        }
    }
}

/// This is the core of the firewall bypass's business logic.
/// Use the run function to create running instances.
#[derive(Debug)]
pub struct OfController<'a> {
    table: &'a OfTable,
    ports: &'a OfPorts,
    stream: Stream,
    hello_received: bool,
    records: &'a RefCell<HashSet<BypassRecord>>,
    rx: &'a Receiver<HashSet<BypassRecord>>,
    refresh_timer: Instant,
}

impl<'a> OfController<'a> {
    fn send_flow_mod(
        &mut self,
        cmd: OfpFlowModCommand,
        mut match_field: OfpMatch,
        input_port: &OfPort,
        output_port: &OfPort,
        prio: u16,
    ) -> io::Result<()> {
        let in_tlv = OfpOxmTlv::new_in_port(input_port.of_port());
        match_field.add_tlv(in_tlv);

        let output = OfpActionOutput::new(output_port.of_port());
        let instr = vec![OfpInstructionActions::new(vec![output])];

        let flow_mod = OfpFlowMod::new(
            cmd,
            self.table.id(),
            prio,
            output_port.of_port(),
            match_field,
            instr,
        );

        trace!("Outgoing message: {:?}", flow_mod);
        flow_mod.serialize(&mut self.stream, gen_xid())
    }

    fn add_basic_flow_mods(&mut self) -> io::Result<()> {
        let p = self.ports;
        let cmd = OfpFlowModCommand::Add;
        let prio = BASIC_FLOW_PRIORITY;
        self.send_flow_mod(cmd, OfpMatch::new(), p.inside(), p.fw_in(), prio)?;
        self.send_flow_mod(cmd, OfpMatch::new(), p.fw_in(), p.inside(), prio)?;
        self.send_flow_mod(cmd, OfpMatch::new(), p.outside(), p.fw_out(), prio)?;
        self.send_flow_mod(cmd, OfpMatch::new(), p.fw_out(), p.outside(), prio)
    }

    fn send_bypass_flow_mods(
        &mut self,
        cmd: OfpFlowModCommand,
        records: &HashSet<BypassRecord>,
    ) -> io::Result<()> {
        for rec in records {
            let mat = OfpMatch::from(rec);
            let (input, output) = self.ports.in_out_from_direction(rec.direction());
            self.send_flow_mod(cmd, mat, input, output, OFP_DEFAULT_PRIORITY)?;
        }
        Ok(())
    }

    fn handle_ofp_message(&mut self, header: &OfpHeader) -> Result<()> {
        debug!("Incoming message: {:?}", header);

        // Read the body
        let mut buf = vec![0; header.body_length()];
        self.stream.read_exact(&mut buf)?;

        // Process the message
        let t = header.typ();
        if t == OfpType::Hello as u8 {
            // simple version discovery
            if header.version() < OFP_VERSION {
                return Err(Error::HelloFailed);
            }
            self.hello_received = true;
            let req = OfpHeader::new(OfpType::FeaturesRequest, gen_xid());
            req.serialize(&mut self.stream)?;
        }
        else if !self.hello_received || header.version() != OFP_VERSION {
            return Err(Error::BadRequest(OfpBadRequestCode::BadVersion, buf));
        }
        else if t == OfpType::EchoRequest as u8 {
            // The EchoReply takes the same body byte stream as the EchoRequest
            let req = OfpEchoRequest::deserialize(buf)?;
            let rep = OfpEchoReply::new(req.arbitrary());
            rep.serialize(&mut self.stream, header.xid())?;
        }
        else if t == OfpType::FeaturesReply as u8 {
            let features = OfpSwitchFeatures::deserialize(buf)?;
            let datapath_id = features.datapath_id();
            info!(
                "The connected switch identified itself with datapath id {}",
                datapath_id
            );

            // unsubscribe from all messages
            let async_conf = OfpAsyncConfig::default();
            async_conf.serialize(&mut self.stream, gen_xid())?;

            self.add_basic_flow_mods()?;

            self.send_bypass_flow_mods(OfpFlowModCommand::Add, &self.records.borrow())?;
        }
        else if t == OfpType::PortStatus as u8 {
            // Ignore. Can be received before unsubscribing via OfpType::SetAsync.
            trace!("Ignoring Port Status Message");
        }
        else if t == OfpType::Error as u8 {
            let error = OfpErrorMsg::deserialize(buf)?;
            error.fail_on_bad_port()?;
            if error.check_table_full() {
                error!(
                    "Table 0 does not have enough free memory for a new Flow. {} {}",
                    "The implementation could be changed to allow for using more tables.", error
                );
            }
            else {
                error!("Unexpected {}", error);
                debug!("Full error message: {:?}", error);
            }
        }
        else {
            debug!(
                "Cannot interpret message of type {}. Full message body: {:?}",
                header.typ(),
                buf
            );
            return Err(Error::BadRequest(OfpBadRequestCode::BadType, buf));
        }
        Ok(())
    }

    /// Checks the inter-thread channel for new messages,
    /// constructs and sends a flow mod for each new/changed `BypassRecord`.
    /// Refreshes all flow entries each hour.
    fn handle_bypass_records(&mut self) -> io::Result<()> {
        match self.rx.try_recv() {
            Ok(new_records) => {
                let del_set = self.records.borrow().sub(&new_records);
                self.send_bypass_flow_mods(OfpFlowModCommand::DeleteStrict, &del_set)?;
                for to_delete in del_set {
                    self.records.borrow_mut().remove(&to_delete);
                }

                let add_set = new_records.sub(&self.records.borrow());
                self.send_bypass_flow_mods(OfpFlowModCommand::Add, &add_set)?;
                for to_add in add_set {
                    self.records.borrow_mut().insert(to_add);
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                panic!("inter-thread communication failed");
            }
        };
        if self.refresh_timer.elapsed() > Duration::from_secs(FLOW_REFRESH_SECS) {
            self.send_bypass_flow_mods(OfpFlowModCommand::Add, &self.records.borrow())?;
            self.refresh_timer = Instant::now();
        }
        Ok(())
    }

    fn handle_of_errors(
        &mut self,
        error: Error,
        header: &OfpHeader,
        header_buf: &[u8],
    ) -> io::Result<()> {
        let err_msg = match error {
            Error::Io(e) => return Err(e),
            Error::HelloFailed => {
                let msg = format!(
                    "The connected switch supports only OpenFlow protocol version {:x}",
                    header.version()
                );
                let err = OfpErrorMsg::new_hello_failed();
                err.serialize(&mut self.stream, header.xid())?;
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, msg));
            }
            Error::BadRequest(code, buf) => OfpErrorMsg::new_bad_request(code, header_buf, &buf),
        };
        debug!("Outgoing error message: {:?}", err_msg);
        err_msg.serialize(&mut self.stream, header.xid())
    }

    /// Manages the lifetime of a controller by accepting a TCP connection,
    /// sending a Hello message and handling incoming messages both from
    /// network and inter-thread channel.
    /// Is an implicit factory for OfController instances.
    pub fn run(
        rx: &Receiver<HashSet<BypassRecord>>,
        listener: &TcpListener,
        connection: &OfConnection,
        table: &OfTable,
        ports: &OfPorts,
        records: &RefCell<HashSet<BypassRecord>>,
    ) -> tls_api::Result<()> {
        let (stream, addr) = listener.accept()?;
        info!("connection from {}", addr);

        let stream = Stream::from(connection, stream)?;

        let mut ctrl = OfController {
            table: table,
            ports: ports,
            stream: stream,
            hello_received: false,
            records: records,
            rx: rx,
            refresh_timer: Instant::now(),
        };

        // Send a Hello
        // Rely on the simple version: If one Hello is empty,
        // the smaller OfpHeader::version is agreed upon
        let hello = OfpHeader::new(OfpType::Hello, gen_xid());
        hello.serialize(&mut ctrl.stream)?;

        loop {
            // Read the header
            let mut hbuf = [0; 8];
            ctrl.stream.read_exact(&mut hbuf)?;
            let header = OfpHeader::deserialize(&hbuf);
            let msg_res = ctrl.handle_ofp_message(&header);
            if msg_res.is_err() {
                ctrl.handle_of_errors(msg_res.unwrap_err(), &header, &hbuf)?;
            }
            if ctrl.hello_received {
                ctrl.handle_bypass_records()?;
            }
        }
    }
}
