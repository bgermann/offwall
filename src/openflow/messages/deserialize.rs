/*!
All deserialization routines for the OpenFlow message primitives

The header uses a special deserialization because its size is known.
Use the trait `Deserialize` for any other deserialization implementation.
*/

use byteorder::{ByteOrder, NetworkEndian};
use openflow::error::{Error, Result};
use openflow::messages::*;

use std::io;
use std::mem::size_of;

impl OfpHeader {
    /// Deserializes an OpenFlow header
    pub fn deserialize(bytes: &[u8; 8]) -> OfpHeader {
        OfpHeader {
            version: bytes[0],
            typ: bytes[1],
            length: NetworkEndian::read_u16(&bytes[2..4]),
            xid: NetworkEndian::read_u32(&bytes[4..]),
        }
    }

    /// Returns the body length in byte
    pub fn body_length(&self) -> usize {
        self.length as usize - OfpHeader::header_length()
    }
}

/// To be implemented by all OpenFlow message parts that are received.
pub trait Deserialize {
    /// The type to deserialize
    type R;

    /// Deserialize the bytes buffer
    /// Fails on providing a too small or too large buffer
    fn deserialize(bytes: Vec<u8>) -> Result<Self::R> {
        if Self::min_length() > bytes.len() || Self::max_length() < bytes.len() {
            return Err(Error::BadRequest(OfpBadRequestCode::BadLen, bytes));
        }
        Self::deserialize_len_ok(bytes)
    }

    /// Deserializes the byte buffer (network byte order)
    /// Implementers can rely on the bytes buffer's size to be greater or equal Self::min_length()
    fn deserialize_len_ok(bytes: Vec<u8>) -> Result<Self::R>;

    /// The minimum length of the message part in bytes
    /// If Self::R contains dynamically sized fields,
    /// you probably have to override this implementation.
    fn min_length() -> usize {
        size_of::<Self::R>()
    }

    /// The maximum length of the message part in bytes
    /// May not return a value greater than 0xFFF7
    /// If Self::R is fixed size, you probably have to
    /// override this implementation.
    fn max_length() -> usize {
        0xffff - OfpHeader::header_length()
    }
}

impl Deserialize for OfpEchoRequest {
    type R = OfpEchoRequest;

    fn deserialize_len_ok(bytes: Vec<u8>) -> Result<Self::R> {
        Ok(OfpEchoRequest { arbitrary: bytes })
    }

    fn min_length() -> usize {
        0
    }
}

impl Deserialize for OfpSwitchFeatures {
    type R = OfpSwitchFeatures;

    fn deserialize_len_ok(bytes: Vec<u8>) -> Result<Self::R> {
        Ok(OfpSwitchFeatures {
            datapath_id: NetworkEndian::read_u64(&bytes[0..8]),
            n_buffers: NetworkEndian::read_u32(&bytes[8..12]),
            n_tables: bytes[12],
            auxiliary_id: bytes[13],
            pad: [bytes[14], bytes[15]],
            capabilities: NetworkEndian::read_u32(&bytes[16..20]),
            reserved: NetworkEndian::read_u32(&bytes[20..]),
        })
    }

    fn max_length() -> usize {
        24
    }
}

impl Deserialize for OfpErrorMsg {
    type R = OfpErrorMsg;

    fn deserialize_len_ok(bytes: Vec<u8>) -> Result<Self::R> {
        let typ = NetworkEndian::read_u16(&bytes[0..2]);
        let code = NetworkEndian::read_u16(&bytes[2..4]);
        Ok(OfpErrorMsg {
            typ: typ,
            code: code,
            data: bytes[4..].to_vec(),
        })
    }

    fn min_length() -> usize {
        4
    }
}

impl OfpErrorMsg {
    /// Fail if the error message is OfpErrorType::BadAction
    /// with OfpBadActionCode::BadOutPort
    pub fn fail_on_bad_port(&self) -> io::Result<()> {
        if self.typ == OfpErrorType::BadAction as u16
            && self.code == OfpBadActionCode::BadOutPort as u16
        {
            // This error is caused by an `OfpFlowMod`.
            // Deserialize its `out_port` field
            let msg = if self.data.len() < 40 {
                "A configured switch port number does not exist.".to_owned()
            }
            else {
                let out_port = NetworkEndian::read_u32(&self.data[36..40]);
                format!("Switch port number {} does not exist.", out_port)
            };
            Err(io::Error::new(io::ErrorKind::BrokenPipe, msg))
        }
        else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_deserialization() {
        let expected = OfpHeader {
            version: 3,
            typ: 1,
            length: 0x5234,
            xid: 0x12345678,
        };
        let bytes = [3, 1, 0x52, 0x34, 0x12, 0x34, 0x56, 0x78];
        assert_eq!(expected, OfpHeader::deserialize(&bytes));
    }

    #[test]
    fn min_lengths() {
        assert_eq!(0, OfpEchoRequest::min_length());
        assert_eq!(24, OfpSwitchFeatures::min_length());
        assert_eq!(4, OfpErrorMsg::min_length());
    }

    #[test]
    fn max_lengths() {
        assert_eq!(0xFFF7, OfpEchoRequest::max_length());
        assert_eq!(24, OfpSwitchFeatures::max_length());
        assert_eq!(0xFFF7, OfpErrorMsg::max_length());
    }
}
