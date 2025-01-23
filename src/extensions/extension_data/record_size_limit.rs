use crate::{
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

/// Maximum record size
///
/// RFC 8449
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RecordSizeLimit(u16);

impl RecordSizeLimit {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let limit = buf.read_u16()?;
        if limit <= 2_u16.pow(14) + 1 {
            Ok(RecordSizeLimit(limit))
        } else {
            warn!("RecordSizeLimit too large: {}", limit);
            Err(ParseError::InvalidData)
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.0).map_err(|_| TlsError::EncodeError)
    }
}
