/*!
All serialization and construction routines for the OpenFlow message primitives

Use the trait `OfpPacket` for serialization implementations of messages
that are sent. Other primitives that are part of a message should
implement a serialize funtion that operates on a given byte stream.
*/

use byteorder::{NetworkEndian, WriteBytesExt};
use bypass_csv::BypassRecord;
use openflow::messages::*;
use std::convert::From;
use std::io;
use std::io::Write;
use std::mem::size_of;

impl OfpHeader {
    /// Constructs an `OfpHeader`
    pub fn new(typ: OfpType, xid: u32) -> OfpHeader {
        OfpHeader {
            version: OFP_VERSION,
            typ: typ as u8,
            length: OfpHeader::header_length() as u16,
            xid: xid,
        }
    }

    /// Returns the fixed header length of 8 (in byte)
    pub fn header_length() -> usize {
        size_of::<OfpHeader>()
    }

    /// Returns the body length in byte
    pub fn body_length(&self) -> usize {
        self.length as usize - OfpHeader::header_length()
    }

    /// Serializes this header on the given stream
    pub fn serialize<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        stream.write_all(&[self.version, self.typ])?;
        stream.write_u16::<NetworkEndian>(self.length)?;
        stream.write_u32::<NetworkEndian>(self.xid)
    }
}

impl OfpMatch {
    /// Constructs an empty match.
    pub fn new() -> OfpMatch {
        OfpMatch {
            typ: OfpMatchType::Oxm as u16,
            oxm_fields: vec![],
        }
    }

    /// Adds a single match field to the match.
    pub fn add_tlv(&mut self, oxm_tlv: OfpOxmTlv) -> &mut OfpMatch {
        self.oxm_fields.push(oxm_tlv);
        self
    }

    /// Length of OfpMatch (excluding padding)
    fn length(&self) -> usize {
        let mut length = 4;
        for oxm in &self.oxm_fields {
            length += oxm.length();
        }
        length
    }

    /// Padding of OfpMatch
    fn pad_len(&self) -> usize {
        let len = self.length();
        (len + 7) / 8 * 8 - len
    }

    fn serialize<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        stream.write_u16::<NetworkEndian>(self.typ)?;
        stream.write_u16::<NetworkEndian>(self.length() as u16)?;
        for oxm in &self.oxm_fields {
            oxm.serialize(stream)?;
        }
        // make its overall size a multiple of 8; fill with zeros
        stream.write_all(&vec![0; self.pad_len()])
    }
}

impl<'a> From<&'a BypassRecord> for OfpMatch {
    fn from(rec: &'a BypassRecord) -> Self {
        let mut mat = OfpMatch::new();
        mat.add_tlv(OfpOxmTlv::new_eth_type_ipv4());
        if let Some(ref ip) = rec.src_ip() {
            let src_ip = OfpOxmTlv::new_ipv4(ip, &ProtocolEndpoint::Src);
            mat.add_tlv(src_ip);
        }
        if let Some(ref ip) = rec.dst_ip() {
            let dst_ip = OfpOxmTlv::new_ipv4(ip, &ProtocolEndpoint::Dst);
            mat.add_tlv(dst_ip);
        }
        if let Some(ref proto) = rec.proto() {
            let oxm_proto = OfpOxmTlv::new_ip_proto(proto);
            mat.add_tlv(oxm_proto);
            if let Some(port) = rec.src_port() {
                if let Some(oxm_port) = OfpOxmTlv::new_port(proto, port, &ProtocolEndpoint::Src) {
                    mat.add_tlv(oxm_port);
                }
            }
            if let Some(port) = rec.dst_port() {
                if let Some(oxm_port) = OfpOxmTlv::new_port(proto, port, &ProtocolEndpoint::Dst) {
                    mat.add_tlv(oxm_port);
                }
            }
        }
        mat
    }
}

impl OfpOxmTlv {
    fn length(&self) -> usize {
        4 + self.body.len()
    }

    fn serialize<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        let class = self.class as u32;
        let hasmask_u32 = if self.hasmask { 1 } else { 0 };
        let header = ((class) << 16) | ((self.field as u32) << 9) | (hasmask_u32 << 8)
            | self.body.len() as u32;
        stream.write_u32::<NetworkEndian>(header)?;
        stream.write_all(&self.body)
    }
}

impl OfpActionOutput {
    /// Constructs an `OfpActionOutput`
    pub fn new(port: u32) -> OfpActionOutput {
        OfpActionOutput {
            typ: OfpActionType::Output as u16,
            len: size_of::<OfpActionOutput>() as u16,
            port: port,
            max_len: 0,
            pad: [0; 6],
        }
    }

    fn serialize<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        stream.write_u16::<NetworkEndian>(self.typ)?;
        stream.write_u16::<NetworkEndian>(self.len)?;
        stream.write_u32::<NetworkEndian>(self.port)?;
        stream.write_u16::<NetworkEndian>(self.max_len)?;
        stream.write_all(&self.pad)
    }
}

impl OfpInstructionActions {
    /// Constructs an `OfpInstructionActions`
    pub fn new(actions: Vec<OfpActionOutput>) -> OfpInstructionActions {
        OfpInstructionActions {
            typ: OfpInstructionType::ApplyActions as u16,
            pad: [0; 4],
            actions: actions,
        }
    }

    fn serialize<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        let actions = &mut vec![];
        for action in &self.actions {
            action.serialize(actions)?;
        }
        stream.write_u16::<NetworkEndian>(self.typ)?;
        stream.write_u16::<NetworkEndian>(8 + actions.len() as u16)?;
        stream.write_all(&self.pad)?;
        stream.write_all(actions)
    }
}

impl OfpFlowMod {
    /// Constructs an `OfpFlowMod` with the given fields.
    /// The other fields are aligned with the use in a firewall bypass.
    pub fn new(
        command: OfpFlowModCommand,
        table_id: u8,
        priority: u16,
        out_port: u32,
        match_field: OfpMatch,
        instructions: Vec<OfpInstructionActions>,
    ) -> OfpFlowMod {
        OfpFlowMod {
            cookie: 0,
            cookie_mask: 0,
            table_id: table_id,
            command: command as u8,
            idle_timeout: OFP_FLOW_PERMANENT,
            hard_timeout: OFP_FLOW_PERMANENT,
            priority: priority,
            buffer_id: OFP_NO_BUFFER,
            out_port: out_port,
            out_group: OFPP_ANY,
            flags: 0,
            pad: [0; 2],
            match_field: match_field,
            instructions: instructions,
        }
    }
}

/// An OpenFlow packet. Must be implemented for all OpenFlow messsages that are sent.
pub trait OfpPacket {
    /// Constructs an OfpHeader with the given body length and transaction ID
    fn header(&self, body_length: usize, xid: u32) -> OfpHeader {
        OfpHeader {
            version: OFP_VERSION,
            typ: Self::typ() as u8,
            length: (OfpHeader::header_length() + body_length) as u16,
            xid: xid,
        }
    }

    /// Returns the packet's type
    fn typ() -> OfpType;

    /// Serializes this packet with network byte order.
    /// The xid is used as its header's transaction id.
    fn serialize<S: Write>(&self, stream: &mut S, xid: u32) -> io::Result<()> {
        let mut body = vec![];
        self.serialize_body(&mut body)?;
        let header = self.header(body.len(), xid);
        debug!("Outgoing message: {:?}", header);
        header.serialize(stream)?;
        stream.write_all(&body)
    }

    /// Serializes this packet's body.
    /// Implementers have to output network byte order on the given stream.
    fn serialize_body<S: Write>(&self, stream: &mut S) -> io::Result<()>;
}

impl OfpEchoReply {
    /// Constructs a new `OfpEchoReply` with `arbitrary` content.
    /// This should be the same as in the `OfpEchoRequest` that issued this reply.
    pub fn new(arbitrary: Vec<u8>) -> OfpEchoReply {
        OfpEchoReply {
            arbitrary: arbitrary,
        }
    }
}
impl OfpPacket for OfpEchoReply {
    fn typ() -> OfpType {
        OfpType::EchoReply
    }

    fn serialize_body<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        stream.write_all(&self.arbitrary)
    }
}

impl OfpPacket for OfpErrorMsg {
    fn typ() -> OfpType {
        OfpType::Error
    }

    fn serialize_body<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        stream.write_u16::<NetworkEndian>(self.typ)?;
        stream.write_u16::<NetworkEndian>(self.code)?;
        stream.write_all(&self.data)
    }
}

impl OfpPacket for OfpFlowMod {
    fn typ() -> OfpType {
        OfpType::FlowMod
    }

    fn serialize_body<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        stream.write_u64::<NetworkEndian>(self.cookie)?;
        stream.write_u64::<NetworkEndian>(self.cookie_mask)?;
        stream.write_all(&[self.table_id, self.command])?;
        stream.write_u16::<NetworkEndian>(self.idle_timeout)?;
        stream.write_u16::<NetworkEndian>(self.hard_timeout)?;
        stream.write_u16::<NetworkEndian>(self.priority)?;
        stream.write_u32::<NetworkEndian>(self.buffer_id)?;
        stream.write_u32::<NetworkEndian>(self.out_port)?;
        stream.write_u32::<NetworkEndian>(self.out_group)?;
        stream.write_u16::<NetworkEndian>(self.flags)?;
        stream.write_all(&self.pad)?;
        self.match_field.serialize(stream)?;
        for instr in &self.instructions {
            instr.serialize(stream)?;
        }
        Ok(())
    }
}

impl OfpPacket for OfpAsyncConfig {
    fn typ() -> OfpType {
        OfpType::SetAsync
    }

    fn serialize_body<S: Write>(&self, stream: &mut S) -> io::Result<()> {
        stream.write_u32::<NetworkEndian>(self.packet_in_mask[0])?;
        stream.write_u32::<NetworkEndian>(self.packet_in_mask[1])?;
        stream.write_u32::<NetworkEndian>(self.port_status_mask[0])?;
        stream.write_u32::<NetworkEndian>(self.port_status_mask[1])?;
        stream.write_u32::<NetworkEndian>(self.flow_removed_mask[0])?;
        stream.write_u32::<NetworkEndian>(self.flow_removed_mask[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_reply_header() {
        let xid = 42;
        let expected = OfpHeader {
            version: 4,
            typ: 3,
            length: 8,
            xid: xid,
        };
        let testee = OfpEchoReply { arbitrary: vec![] };
        assert_eq!(expected, testee.header(0, xid));
    }

    #[test]
    fn echo_reply_body_serialization() {
        let arbitrary = vec![1, 2, 3, 4];
        let testee = OfpEchoReply {
            arbitrary: arbitrary,
        };
        let mut ser = vec![];
        testee.serialize_body(&mut ser).unwrap();
        assert_eq!(vec![1, 2, 3, 4], ser);
        assert_eq!(12, testee.header(ser.len(), 1).length);
    }

    #[test]
    fn oxm_tlv_serialization() {
        let testee = OfpOxmTlv::new_in_port(0x11223344);
        assert_eq!(8, testee.length());
        assert_eq!(vec![0x11, 0x22, 0x33, 0x44], testee.body);
    }

    #[test]
    fn match_serialization() {
        let tlv = OfpOxmTlv::new_in_port(1);
        let mut testee = OfpMatch::new();
        testee.add_tlv(tlv);
        assert_eq!(12, testee.length());
        assert_eq!(4, testee.pad_len());
        let mut ser = vec![];
        testee.serialize(&mut ser).unwrap();
        assert_eq!(16, ser.len());
    }

    #[test]
    fn action_output_serialization() {
        let testee = OfpActionOutput::new(0x11223344);
        let mut ser = vec![];
        testee.serialize(&mut ser).unwrap();
        assert_eq!(16, ser.len());
        assert_eq!(
            vec![0, 0, 0, 16, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0],
            ser
        );
    }

}
