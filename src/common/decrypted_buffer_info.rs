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
