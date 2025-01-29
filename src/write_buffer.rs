use crate::{
    buffer::CryptoBuffer,
    config::{TlsCipherSuite, TLS_RECORD_OVERHEAD},
    connection::encrypt,
    key_schedule::{ReadKeySchedule, WriteKeySchedule},
    record::{ClientRecord, ClientRecordHeader},
    TlsError,
};

pub struct WriteBufferInfo {
    /// Current write position, relative to the last closed record.
    pos: usize,
    /// Current submitted position (closed records that are ready to be transmitted).
    record_offset: usize,
    current_header: Option<ClientRecordHeader>,
}

impl WriteBufferInfo {
    pub fn empty() -> Self {
        Self {
            pos: 0,
            record_offset: 0,
            current_header: None,
        }
    }

    pub fn pending_bytes(&self) -> usize {
        self.record_offset + self.pos
    }
}

pub struct WriteBuffer<'a> {
    buffer: &'a mut [u8],
    info: WriteBufferInfo,
}

impl<'a> WriteBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        debug_assert!(
            buffer.len() > TLS_RECORD_OVERHEAD,
            "The write buffer must be sufficiently large to include the tls record overhead"
        );
        Self {
            buffer,
            info: WriteBufferInfo {
                pos: 0,
                record_offset: 0,
                current_header: None,
            },
        }
    }

    /// Reassembles a write buffer in a non-blocking context.
    /// Unlike the usage of the WriteBuffer in the blocking variant, this does not require
    /// there to be sufficient space in the write buffer for the TLS record overhead;
    /// `start_record()` and `close_record()` will return `TlsError::WouldBlock` in these cases.
    pub fn from_info(buffer: &'a mut [u8], info: WriteBufferInfo) -> Self {
        assert!(info.record_offset + info.pos <= buffer.len());
        Self { buffer, info }
    }

    /// Removes the buffer reference, only retains the buffer info. Returns the
    /// number of completed (`record_offset`) octets, and fixes up the returned
    /// WriteBufferInfo to accomodate the dropped octets.
    pub fn into_info(self) -> (usize, WriteBufferInfo) {
        (
            self.info.record_offset,
            WriteBufferInfo {
                record_offset: 0,
                ..self.info
            },
        )
    }

    fn max_block_size(&self) -> usize {
        // `max_block_size` is invalid to call if there is no space for the overhead.
        assert!(self.buffer.len() >= TLS_RECORD_OVERHEAD);
        self.buffer.len() - TLS_RECORD_OVERHEAD
    }

    pub fn is_full(&self) -> bool {
        self.info.record_offset + self.info.pos == self.max_block_size()
    }

    pub fn append(&mut self, buf: &[u8]) -> usize {
        let buffered = usize::min(buf.len(), self.space());
        if buffered > 0 {
            self.buffer[self.info.record_offset + self.info.pos
                ..self.info.record_offset + self.info.pos + buffered]
                .copy_from_slice(&buf[..buffered]);
            self.info.pos += buffered;
        }
        buffered
    }

    pub fn len(&self) -> usize {
        self.info.pos
    }

    /// Returns whether there is no incomplete record in the buffer.
    /// Completed records (when in non-blocking) are ignored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn space(&self) -> usize {
        self.max_block_size() - self.info.record_offset - self.info.pos
    }

    pub fn contains(&self, header: ClientRecordHeader) -> bool {
        self.info.current_header == Some(header)
    }

    fn with_buffer(
        &mut self,
        op: impl FnOnce(CryptoBuffer) -> Result<CryptoBuffer, TlsError>,
    ) -> Result<(), TlsError> {
        let buf =
            CryptoBuffer::wrap_with_pos(&mut self.buffer[self.info.record_offset..], self.info.pos);

        match op(buf) {
            Ok(buf) => {
                self.info.pos = buf.len();
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn start_record(&mut self, header: ClientRecordHeader) -> Result<(), TlsError> {
        debug_assert!(self.info.current_header.is_none());

        assert!(self.info.pos == 0);

        // Verify invariant.
        assert!(self.buffer.len() >= self.info.record_offset + self.info.pos);

        // See if there is insufficient space in the buffer for a minimum
        // appliction record. Outside of a non-blocking context, this cannot
        // happen since `::new` verifies that the buffer space is large enough.
        if self.buffer.len() - self.info.record_offset - self.info.pos < TLS_RECORD_OVERHEAD {
            return Err(TlsError::WouldBlock);
        }

        debug!("start_record({:?})", header);
        self.info.current_header = Some(header);

        self.with_buffer(|mut buf| {
            header.encode(&mut buf)?;
            buf.push_u16(0)?;
            Ok(buf.rewind())
        })
    }

    pub(crate) fn close_record<CipherSuite>(
        &mut self,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<&[u8], TlsError>
    where
        CipherSuite: TlsCipherSuite,
    {
        const HEADER_SIZE: usize = 5;

        // Verify invariant.
        assert!(self.buffer.len() >= self.info.record_offset + self.info.pos);
        assert!(TLS_RECORD_OVERHEAD >= HEADER_SIZE);

        // See if there is insufficient space in the buffer to close the record.
        // Outside of a non-blocking context, this cannot happen since `::new`
        // verifies that the buffer space is large enough to fit at least some
        // data, and `append` ensures that enough space is left at the end.
        if self.buffer.len() - self.info.record_offset - self.info.pos
            < (TLS_RECORD_OVERHEAD - HEADER_SIZE)
        {
            return Err(TlsError::WouldBlock);
        }

        let header = self.info.current_header.take().unwrap();
        self.with_buffer(|mut buf| {
            if !header.is_encrypted() {
                return Ok(buf);
            }

            buf.push(header.trailer_content_type() as u8)
                .map_err(|_| TlsError::EncodeError)?;

            let mut buf = buf.offset(HEADER_SIZE);
            encrypt(write_key_schedule, &mut buf)?;
            Ok(buf.rewind())
        })?;
        let [upper, lower] = ((self.info.pos - HEADER_SIZE) as u16).to_be_bytes();

        self.buffer[self.info.record_offset + 3] = upper;
        self.buffer[self.info.record_offset + 4] = lower;

        let slice = &self.buffer[self.info.record_offset..self.info.record_offset + self.info.pos];

        self.info.record_offset += self.info.pos;
        self.info.pos = 0;
        self.info.current_header = None;

        Ok(slice)
    }

    pub fn write_record<CipherSuite>(
        &mut self,
        record: &ClientRecord<CipherSuite>,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
        read_key_schedule: Option<&mut ReadKeySchedule<CipherSuite>>,
    ) -> Result<&[u8], TlsError>
    where
        CipherSuite: TlsCipherSuite,
    {
        if self.info.current_header.is_some() {
            return Err(TlsError::InternalError);
        }

        // In a non-blocking context, starting a record could fail due to insufficient buffer space.
        self.start_record(record.header())?;

        // FIXME: these records can be longer than what we have reserved.
        // At this point, we are committed - we can't bail out with
        // `TlsError::WouldBlock` if the buffer is too small.

        self.with_buffer(|buf| {
            let mut buf = buf.forward();
            record.encode_payload(&mut buf)?;

            let transcript = read_key_schedule
                .ok_or(TlsError::InternalError)?
                .transcript_hash();

            record.finish_record(&mut buf, transcript, write_key_schedule)?;
            Ok(buf.rewind())
        })?;
        self.close_record(write_key_schedule)
            .inspect_err(|e| assert!(!matches!(e, TlsError::WouldBlock)))
    }
}
