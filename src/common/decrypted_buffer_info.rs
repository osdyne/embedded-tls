use crate::read_buffer::ReadBuffer;

#[derive(Default)]
pub struct DecryptedBufferInfo {
    pub offset: usize,
    pub len: usize,
    pub consumed: usize,
    // TODO: for simplification, preserve the full decrypted TLS record.
    // (Ideally we would drop the consumed bytes at the start)
    pub record_length: usize,
}

impl DecryptedBufferInfo {
    pub fn create_read_buffer<'b>(&'b mut self, buffer: &'b [u8]) -> ReadBuffer<'b> {
        let offset = self.offset + self.consumed;
        let end = self.offset + self.len;
        ReadBuffer::new(&buffer[offset..end], &mut self.consumed)
    }

    pub fn bytes_to_preserve(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            self.record_length
        }
    }

    pub fn drop_buffer_bytes(&mut self, offset: usize) {
        if !self.is_empty() {
            self.offset -= offset;
        }
    }

    pub fn len(&self) -> usize {
        self.len - self.consumed
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod test {
    use super::DecryptedBufferInfo;

    #[test]
    fn bytes_to_preserve_reflects_record_length() {
        let mut info = DecryptedBufferInfo::default();
        // No pending plaintext: nothing to preserve.
        assert_eq!(info.bytes_to_preserve(), 0);

        // Unconsumed plaintext: preserve the whole encrypted record footprint.
        info.len = 10;
        info.record_length = 64;
        assert_eq!(info.bytes_to_preserve(), 64);

        // Fully consumed: nothing left to preserve.
        info.consumed = 10;
        assert_eq!(info.bytes_to_preserve(), 0);
    }

    #[test]
    fn drop_buffer_bytes_shifts_offset_only_when_nonempty() {
        let mut info = DecryptedBufferInfo {
            offset: 30,
            len: 10,
            consumed: 0,
            record_length: 64,
        };
        info.drop_buffer_bytes(20);
        assert_eq!(info.offset, 10);

        // No pending plaintext: dropping bytes is a no-op.
        let mut empty = DecryptedBufferInfo {
            offset: 5,
            len: 0,
            consumed: 0,
            record_length: 0,
        };
        empty.drop_buffer_bytes(3);
        assert_eq!(empty.offset, 5);
    }
}
