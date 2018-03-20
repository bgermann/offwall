/*!
All the base OpenFlow 1.3 message primitives needed to implement a firewall bypass

This is based on the openflow.h from OpenFlow Switch Specification 1.3.5.
The type names are changed to align with the Rust conventions.
*/

pub mod deserialize;
pub mod serialize;

use byteorder::{ByteOrder, NetworkEndian};
use bypass_csv::IpProtocol;
use ipnetwork::Ipv4Network;
use std::fmt;

/// A marker to express the endpoint
/// of any end-to-end network protocol
pub enum ProtocolEndpoint {
    /// The endpoint is the source
    Src,
    /// The endpoint is the destination
    Dst,
}

impl OfpErrorMsg {
    fn first_64_bytes(header: &[u8], body: &[u8]) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(header);
        let target_length = 64 - header.len();
        let shrunk_body = if body.len() < target_length {
            body
        }
        else {
            &body[0..target_length]
        };
        buf.extend_from_slice(shrunk_body);
        buf
    }

    /// Constructs a Hello Failed error
    pub fn new_hello_failed() -> OfpErrorMsg {
        OfpErrorMsg {
            typ: OfpErrorType::HelloFailed as u16,
            code: OfpHelloFailedCode::Incompatible as u16,
            data: vec![],
        }
    }

    /// Constructs a Bad Request error
    pub fn new_bad_request(code: OfpBadRequestCode, header: &[u8], body: &[u8]) -> OfpErrorMsg {
        OfpErrorMsg {
            typ: OfpErrorType::BadRequest as u16,
            code: code as u16,
            data: Self::first_64_bytes(header, body),
        }
    }

    /// Checks if this `OfpErrorMsg` describes the target OpenFlow Table being full
    pub fn check_table_full(&self) -> bool {
        self.typ == OfpErrorType::FlowModFailed as u16
            && self.code == OfpFlowModFailedCode::TableFull as u16
    }
}

impl fmt::Display for OfpErrorMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let t = self.typ;
        let typ = if t == OfpErrorType::HelloFailed as u16 {
            OfpErrorType::HelloFailed
        }
        else if t == OfpErrorType::BadRequest as u16 {
            OfpErrorType::BadRequest
        }
        else if t == OfpErrorType::BadAction as u16 {
            OfpErrorType::BadAction
        }
        else if t == OfpErrorType::BadInstruction as u16 {
            OfpErrorType::BadInstruction
        }
        else if t == OfpErrorType::BadMatch as u16 {
            OfpErrorType::BadMatch
        }
        else if t == OfpErrorType::FlowModFailed as u16 {
            OfpErrorType::FlowModFailed
        }
        else if t == OfpErrorType::Experimenter as u16 {
            OfpErrorType::Experimenter
        }
        else {
            return write!(f, "OpenFlow Error: type({}), code({})", self.typ, self.code);
        };
        write!(f, "OpenFlow Error: {:?}, code({})", typ, self.code)
    }
}

/* Some getters */

impl OfpHeader {
    /// Gets the packet's OpenFlow version
    pub fn version(&self) -> u8 {
        self.version
    }
    /// Gets this packet's `OfpType`'s numerical respresentation.
    pub fn typ(&self) -> u8 {
        self.typ
    }
    /// Gets the packet's transaction id
    pub fn xid(&self) -> u32 {
        self.xid
    }
}
impl OfpSwitchFeatures {
    /// Gets the datapath unique ID
    pub fn datapath_id(&self) -> u64 {
        self.datapath_id
    }
}
impl OfpEchoRequest {
    /// Gets the message's content
    pub fn arbitrary(self) -> Vec<u8> {
        self.arbitrary
    }
}

/// An OpenFlow Echo Request
#[derive(Debug)]
pub struct OfpEchoRequest {
    arbitrary: Vec<u8>,
}

/// An OpenFlow Echo Reply
#[derive(Debug)]
pub struct OfpEchoReply {
    arbitrary: Vec<u8>,
}

/// An OpenFlow TLV (Type, Length, Value) for
/// the OpenFlow Extensible Match format
#[derive(Debug, Clone)]
pub struct OfpOxmTlv {
    /// Header class
    class: OfpOxmClass,
    /// Header field
    field: OxmOfbMatchFields,
    /// Header hasmask
    hasmask: bool,
    /// Body
    body: Vec<u8>,
}

/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
 * Copyright (c) 2011, 2012 Open Networking Foundation
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/// Version number:
/// OpenFlow versions released: 0x01 = 1.0 ; 0x02 = 1.1 ; 0x03 = 1.2; 0x04 = 1.3.
///
/// The most significant bit in the version field is reserved and must be set to zero.
pub const OFP_VERSION: u8 = 0x04;

/// Maximum number of physical and logical switch ports. Ports are numbered starting from 1.
pub const OFPP_MAX: u32 = 0xffff_ff00;
/// Special value used in some requests when no port is specified (i.e. wildcarded).
pub const OFPP_ANY: u32 = 0xffff_ffff;

/// A message's type, the most fundamental to
/// distinguish information between messages
pub enum OfpType {
    /* Immutable messages. */
    /// Symmetric message
    Hello = 0,
    /// Symmetric message
    Error = 1,
    /// Symmetric message
    EchoRequest = 2,
    /// Symmetric message
    EchoReply = 3,

    /* Switch configuration messages. */
    /// Controller/switch message
    FeaturesRequest = 5,
    /// Controller/switch message
    FeaturesReply = 6,

    /* Asynchronous messages. */
    /// Async message
    PortStatus = 12,

    /* Controller command messages. */
    /// Controller/switch message
    FlowMod = 14,

    /* Asynchronous message configuration. */
    /// Controller/switch message
    SetAsync = 28,
}

/// Header on all OpenFlow packets.
#[derive(Debug, PartialEq)]
pub struct OfpHeader {
    /// OFP_VERSION.
    version: u8,
    /// This packet's OfpType.
    typ: u8,
    /// This packet's length including this OfpHeader.
    length: u16,
    /// Transaction id associated with this packet.
    /// Replies use the same id as was in the request
    /// to facilitate pairing.
    xid: u32,
}

/// Switch features.
#[derive(Debug, PartialEq)]
pub struct OfpSwitchFeatures {
    /// Datapath unique ID. The lower 48-bits are for
    /// a MAC address, while the upper 16-bits are
    /// implementer-defined.
    datapath_id: u64,
    /// Max packets buffered at once.
    n_buffers: u32,
    /// Number of tables supported by datapath.
    n_tables: u8,
    /// Identify auxiliary connections
    auxiliary_id: u8,
    /// Align to 64-bits.
    pad: [u8; 2],

    /* Features. */
    /// Bitmap of support OfpCapabilities.
    capabilities: u32,
    reserved: u32,
}

/* ## -------------------------- ## */
/* ## OpenFlow Extensible Match. ## */
/* ## -------------------------- ## */

/// The match type indicates the match structure (set of fields that compose the match) in use.
///
/// The match type is placed in the type field at the beginning
/// of all match structures. The "OpenFlow Extensible Match" type corresponds
/// to OXM TLV format described below and must be supported by all OpenFlow
/// switches. Extensions that define other match types may be published on the
/// ONF wiki. Support for extensions is optional.
pub enum OfpMatchType {
    /// OpenFlow Extensible Match
    Oxm = 1,
}

/// Fields to match against flows
#[derive(Debug, Clone, Default)]
pub struct OfpMatch {
    /// One of OfpMatchType
    typ: u16,
    // length(): Length of OfpMatch (excluding padding)
    /* Followed by:
     *   - Exactly (length - 4) (possibly 0) bytes containing OXM TLVs, then
     *   - Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of
     *     all-zero bytes
     * In summary, OfpMatch is padded as needed, to make its overall size
     * a multiple of 8, to preserve alignment in structures using it.
     */
    /// 0 or more OXM match fields
    oxm_fields: Vec<OfpOxmTlv>,
    // Zero bytes - see above for sizing
}

/// Construction of an OXM TLV.
impl OfpOxmTlv {
    fn new(field: OxmOfbMatchFields, hasmask: bool, body: Vec<u8>) -> OfpOxmTlv {
        OfpOxmTlv {
            class: OfpOxmClass::OpenflowBasic,
            hasmask,
            field,
            body,
        }
    }

    /// OpenFlow port on which the packet was received.
    /// May be a physical port, a logical port, or the reserved port OFPP_LOCAL
    /// Prereqs: None.
    /// Format: 32-bit integer in network byte order.
    pub fn new_in_port(in_port: u32) -> OfpOxmTlv {
        let mut port_bytes = vec![0; 4];
        NetworkEndian::write_u32(&mut port_bytes, in_port);
        OfpOxmTlv::new(OxmOfbMatchFields::InPort, false, port_bytes)
    }

    /// Packet's Ethernet type.
    /// Prereqs: None.
    /// Format: 16-bit integer in network byte order.
    pub fn new_eth_type_ipv4() -> OfpOxmTlv {
        OfpOxmTlv::new(OxmOfbMatchFields::EthType, false, vec![8, 0])
    }

    /// The "protocol" byte in the IP header.
    /// Prereqs: OxmOfbMatchFields::EthType must be either 0x0800 or 0x86dd.
    /// Format: 8-bit integer.
    pub fn new_ip_proto(proto: &IpProtocol) -> OfpOxmTlv {
        OfpOxmTlv::new(OxmOfbMatchFields::IpProto, false, vec![*proto as u8])
    }

    /// The source or destination address in the IP header.
    /// Prereqs: OxmOfbMatchFields::EthType must match 0x0800 exactly.
    /// Format: 32-bit integer in network byte order.
    /// Masking: Arbitrary masks.
    pub fn new_ipv4(cidr: &Ipv4Network, endpoint: &ProtocolEndpoint) -> OfpOxmTlv {
        let field = match *endpoint {
            ProtocolEndpoint::Src => OxmOfbMatchFields::Ipv4Src,
            ProtocolEndpoint::Dst => OxmOfbMatchFields::Ipv4Dst,
        };
        let mut oxm_val_and_mask = vec![];
        oxm_val_and_mask.extend_from_slice(&cidr.network().octets());
        oxm_val_and_mask.extend_from_slice(&cidr.mask().octets());
        OfpOxmTlv::new(field, true, oxm_val_and_mask)
    }

    /// The source or destination port in the TCP/UDP header.
    /// Prereqs:
    /// OxmOfbMatchFields::EthType must be either 0x0800 or 0x86dd.
    /// OxmOfbMatchFields::IpProto must match 6 or 17 exactly.
    /// Format: 16-bit integer in network byte order.
    pub fn new_port(
        proto: &IpProtocol,
        port: u16,
        endpoint: &ProtocolEndpoint,
    ) -> Option<OfpOxmTlv> {
        let field = match *proto {
            IpProtocol::Tcp => match *endpoint {
                ProtocolEndpoint::Src => OxmOfbMatchFields::TcpSrc,
                ProtocolEndpoint::Dst => OxmOfbMatchFields::TcpDst,
            },
            IpProtocol::Udp => match *endpoint {
                ProtocolEndpoint::Src => OxmOfbMatchFields::UdpSrc,
                ProtocolEndpoint::Dst => OxmOfbMatchFields::UdpDst,
            },
            _ => return None,
        };
        let mut port_bytes = vec![0; 2];
        NetworkEndian::write_u16(&mut port_bytes, port);
        Some(OfpOxmTlv::new(field, false, port_bytes))
    }
}

/// OXM Class IDs.
/// The high order bit differentiate reserved classes from member classes.
/// Classes 0x0000 to 0x7FFF are member classes, allocated by ONF.
/// Classes 0x8000 to 0xFFFE are reserved classes, reserved for standardisation.
#[derive(Debug, Clone, Copy)]
enum OfpOxmClass {
    /// Basic class for OpenFlow
    OpenflowBasic = 0x8000,
}

/// OXM Flow match field types for OpenFlow basic class.
#[derive(Debug, Clone, Copy)]
enum OxmOfbMatchFields {
    /// Switch input port.
    InPort = 0,
    /// Ethernet frame type.
    EthType = 5,
    /// IP protocol.
    IpProto = 10,
    /// IPv4 source address.
    Ipv4Src = 11,
    /// IPv4 destination address.
    Ipv4Dst = 12,
    /// TCP source port.
    TcpSrc = 13,
    /// TCP destination port.
    TcpDst = 14,
    /// UDP source port.
    UdpSrc = 15,
    /// UDP destination port.
    UdpDst = 16,
}

/// Values for 'type' in `OfpErrorMsg`. These values are immutable: they will
/// not change in future versions of the protocol (although new values may be added).
#[derive(Debug)]
pub enum OfpErrorType {
    /// Hello protocol failed.
    HelloFailed = 0,
    /// Request was not understood.
    BadRequest = 1,
    /// Error in action description.
    BadAction = 2,
    /// Error in instruction list.
    BadInstruction = 3,
    /// Error in match.
    BadMatch = 4,
    /// Problem modifying flow entry.
    FlowModFailed = 5,
    /// Experimenter error messages.
    Experimenter = 0xffff,
}

/// `OfpErrorMsg` 'code' values for `OfpErrorType::HelloFailed`.
///
/// 'data' contains an ASCII text string that may give failure details.
pub enum OfpHelloFailedCode {
    /// No compatible version.
    Incompatible = 0,
}

/// `OfpErrorMsg` 'code' values for `OfpErrorType::BadRequest`.
///
/// 'data' contains at least the first 64 bytes of the failed request.
#[derive(Debug)]
pub enum OfpBadRequestCode {
    /// ofp_header.version not supported.
    BadVersion = 0,
    /// ofp_header.type not supported.
    BadType = 1,
    /// Wrong request length for type.
    BadLen = 6,
}

/* ## ----------------- ## */
/* ## OpenFlow Actions. ## */
/* ## ----------------- ## */

/// The type of an OpenFlow Action
pub enum OfpActionType {
    /// Output to switch port.
    Output = 0,
}

/// Action structure for `OfpActionType::Output`, which sends packets out 'port'.
///
/// A `max_len` of zero means no bytes of the packet should be sent to the controller.
#[derive(Debug)]
pub struct OfpActionOutput {
    /// One of `OfpActionType::Output`.
    typ: u16,
    /// Length is 16. The length includes the header and
    /// any padding used to make the action 64-bit aligned.
    len: u16,
    /// Output port.
    port: u32,
    /// Max length to send to controller.
    max_len: u16,
    /// Pad to 64 bits.
    pad: [u8; 6],
}

/* ## ---------------------- ## */
/* ## OpenFlow Instructions. ## */
/* ## ---------------------- ## */

/// The type of an OpenFlow Instruction
pub enum OfpInstructionType {
    /// Applies the action(s) immediately
    ApplyActions = 4,
}

/// Instruction structure for `OfpInstructionType::ApplyActions`
#[derive(Debug)]
pub struct OfpInstructionActions {
    /// One of `OfpInstructionType`
    typ: u16,
    // len: Length of this struct in bytes. The length includes the header
    // and any padding used to make the instruction 64-bit aligned.
    /// Align to 64-bits
    pad: [u8; 4],
    /// 0 or more actions associated with `OfpInstructionType::ApplyActions`
    actions: Vec<OfpActionOutput>,
}

/* ## --------------------------- ## */
/* ## OpenFlow Flow Modification. ## */
/* ## --------------------------- ## */

/// The command that is embedded in a flow mod message
#[derive(Clone, Copy)]
pub enum OfpFlowModCommand {
    /// New flow.
    Add = 0,
    /// Delete entry strictly matching wildcards and priority.
    DeleteStrict = 4,
}

/// Value used in `idle_timeout` and `hard_timeout` to indicate that the entry is permanent.
pub const OFP_FLOW_PERMANENT: u16 = 0;

/// By default, choose a priority in the middle.
pub const OFP_DEFAULT_PRIORITY: u16 = 0x8000;

/// Flow setup and teardown (controller -> datapath).
#[derive(Debug)]
pub struct OfpFlowMod {
    /// Opaque controller-issued identifier.
    cookie: u64,
    /// Mask used to restrict the cookie bits
    /// that must match when the command is
    /// OfpFlowModCommand::Modify* or OfpFlowModCommand::Delete*.
    /// A value of 0 indicates no restriction.
    cookie_mask: u64,
    /// ID of the table to put the flow in.
    /// For OfpFlowModCommand::Delete* commands,
    /// OFPTT_ALL can also be used to delete
    /// matching flows from all tables.
    table_id: u8,
    /// One of OfpFlowModCommand.
    command: u8,
    /// Idle time before discarding (seconds).
    idle_timeout: u16,
    /// Max time before discarding (seconds).
    hard_timeout: u16,
    /// Priority level of flow entry.
    priority: u16,
    /// Buffered packet to apply to, or
    /// OFP_NO_BUFFER.
    /// Not meaningful for OfpFlowModCommand::Delete*.
    buffer_id: u32,
    /// For OfpFlowModCommand::Delete* commands, require
    /// matching entries to include this as an
    /// output port.  A value of OfpPortNo::Any
    /// indicates no restriction.
    out_port: u32,
    /// For OfpFlowModCommand::Delete* commands, require
    /// matching entries to include this as an
    /// output group.  A value of OfpPortNo::Any
    /// indicates no restriction.
    out_group: u32,
    /// Bitmap of OfpFlowModFlags.
    flags: u16,
    pad: [u8; 2],
    /// Fields to match. Variable size.
    match_field: OfpMatch,

    /* The variable size and padded match is always followed by instructions. */
    /// Instruction set - 0 or more.
    /// The length of the instruction
    /// set is inferred from the
    /// length field in the header.
    instructions: Vec<OfpInstructionActions>,
}

/// A reserved buffer ID to express that no buffer is assigned
pub const OFP_NO_BUFFER: u32 = 0xffff_ffff;

/// `OfpErrorMsg` 'code' values for `OfpErrorType::BadAction`.
///
/// 'data' contains at least the first 64 bytes of the failed request.
pub enum OfpBadActionCode {
    /// Poblem validating output port
    BadOutPort = 4,
}

/// `OfpErrorMsg` 'code' values for `OfpErrorType::FlowModFailed`.
///
/// 'data' contains at least the first 64 bytes of the failed request.
#[derive(Debug)]
pub enum OfpFlowModFailedCode {
    /// Flow not added because table was full.
    TableFull = 1,
}

/// Error message (datapath -> controller).
#[derive(Debug)]
pub struct OfpErrorMsg {
    typ: u16,
    code: u16,
    /// Variable-length data. Interpreted based on the type and code. No padding.
    data: Vec<u8>,
}

/// Asynchronous message configuration.
#[derive(Default)]
pub struct OfpAsyncConfig {
    /// Bitmasks of OFPR_* values.
    packet_in_mask: [u32; 2],
    /// Bitmasks of OFPPR_* values.
    port_status_mask: [u32; 2],
    /// Bitmasks of OFPRR_* values.
    flow_removed_mask: [u32; 2],
}
