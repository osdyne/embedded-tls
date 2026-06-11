use crate::{
    TlsError,
    buffer::CryptoBuffer,
    config::{TLS_RECORD_OVERHEAD, TlsCipherSuite},
    connection::encrypt,
    key_schedule::{ReadKeySchedule, WriteKeySchedule},
    record::{ClientRecord, ClientRecordHeader},
};

pub struct WriteBufferInfo {
    /// Current write position, relative to the last closed record.
    pos: usize,
    /// Current submitted position (closed records that are ready to be transmitted).
    record_offset: usize,
    current_header: Option<ClientRecordHeader>,
    nonblocking: bool,
}

impl WriteBufferInfo {
    pub fn empty() -> Self {
        Self {
            pos: 0,
            record_offset: 0,
            current_header: None,
            nonblocking: true,
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

pub(crate) struct WriteBufferBorrow<'a> {
    buffer: &'a [u8],
    info: &'a WriteBufferInfo,
}

pub(crate) struct WriteBufferBorrowMut<'a> {
    buffer: &'a mut [u8],
    info: &'a mut WriteBufferInfo,
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
                nonblocking: false,
            },
        }
    }

    /// Reassembles a write buffer in a non-blocking context.
    /// Unlike the usage of the `WriteBuffer` in the blocking variant, this does not require
    /// there to be sufficient space in the write buffer for the TLS record overhead;
    /// `start_record()` and `close_record()` will return `TlsError::WouldBlock` in these cases.
    pub fn from_info(buffer: &'a mut [u8], info: WriteBufferInfo) -> Self {
        assert!(info.record_offset + info.pos <= buffer.len());
        Self { buffer, info }
    }

    /// Removes the buffer reference, only retains the buffer info. Returns the
    /// number of completed (`record_offset`) octets, and fixes up the returned
    /// `WriteBufferInfo` to accomodate the dropped octets.
    pub fn into_info(self) -> (usize, WriteBufferInfo) {
        (
            self.info.record_offset,
            WriteBufferInfo {
                record_offset: 0,
                ..self.info
            },
        )
    }

    pub(crate) fn reborrow_mut(&mut self) -> WriteBufferBorrowMut<'_> {
        WriteBufferBorrowMut {
            buffer: self.buffer,
            info: &mut self.info,
        }
    }

    pub(crate) fn reborrow(&self) -> WriteBufferBorrow<'_> {
        WriteBufferBorrow {
            buffer: self.buffer,
            info: &self.info,
        }
    }

    pub fn is_full(&self) -> bool {
        self.reborrow().is_full()
    }

    pub fn append(&mut self, buf: &[u8]) -> usize {
        self.reborrow_mut().append(buf)
    }

    pub fn is_empty(&self) -> bool {
        self.reborrow().is_empty()
    }

    pub fn contains(&self, header: ClientRecordHeader) -> bool {
        self.reborrow().contains(header)
    }

    pub(crate) fn start_record(&mut self, header: ClientRecordHeader) -> Result<(), TlsError> {
        self.reborrow_mut().start_record(header)
    }

    pub(crate) fn close_record<CipherSuite>(
        &mut self,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<&[u8], TlsError>
    where
        CipherSuite: TlsCipherSuite,
    {
        close_record(self.buffer, &mut self.info, write_key_schedule)
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
        write_record(
            self.buffer,
            &mut self.info,
            record,
            write_key_schedule,
            read_key_schedule,
        )
    }
}

impl WriteBufferBorrow<'_> {
    fn max_block_size(&self) -> usize {
        // `max_block_size` is invalid to call if there is no space for the overhead.
        assert!(self.buffer.len() >= TLS_RECORD_OVERHEAD);
        self.buffer.len() - TLS_RECORD_OVERHEAD
    }

    pub fn is_full(&self) -> bool {
        self.info.record_offset + self.info.pos == self.max_block_size()
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
}

impl WriteBufferBorrowMut<'_> {
    fn reborrow(&self) -> WriteBufferBorrow<'_> {
        WriteBufferBorrow {
            buffer: self.buffer,
            info: self.info,
        }
    }

    pub fn is_full(&self) -> bool {
        self.reborrow().is_full()
    }

    pub fn is_empty(&self) -> bool {
        self.reborrow().is_empty()
    }

    pub fn contains(&self, header: ClientRecordHeader) -> bool {
        self.reborrow().contains(header)
    }

    pub fn append(&mut self, buf: &[u8]) -> usize {
        let buffered = usize::min(buf.len(), self.reborrow().space());
        if buffered > 0 {
            self.buffer[self.info.record_offset + self.info.pos
                ..self.info.record_offset + self.info.pos + buffered]
                .copy_from_slice(&buf[..buffered]);
            self.info.pos += buffered;
        }
        buffered
    }

    pub(crate) fn start_record(&mut self, header: ClientRecordHeader) -> Result<(), TlsError> {
        start_record(self.buffer, self.info, header)
    }

    pub fn close_record<CipherSuite>(
        &mut self,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<&[u8], TlsError>
    where
        CipherSuite: TlsCipherSuite,
    {
        close_record(self.buffer, self.info, write_key_schedule)
    }
}

fn start_record(
    buffer: &mut [u8],
    info: &mut WriteBufferInfo,
    header: ClientRecordHeader,
) -> Result<(), TlsError> {
    debug_assert!(info.current_header.is_none());

    assert!(info.pos == 0);

    // Verify invariant.
    assert!(buffer.len() >= info.record_offset + info.pos);

    // See if there is insufficient space in the buffer for a minimum
    // application record. Outside of a non-blocking context, this cannot
    // happen since `::new` verifies that the buffer space is large enough.
    if buffer.len() - info.record_offset - info.pos < TLS_RECORD_OVERHEAD {
        return Err(TlsError::WouldBlock);
    }

    debug!("start_record({:?})", header);
    info.current_header = Some(header);

    with_buffer(buffer, info, |mut buf| {
        header.encode(&mut buf)?;
        buf.push_u16(0)?;
        Ok(buf.rewind())
    })
}

fn with_buffer(
    buffer: &mut [u8],
    info: &mut WriteBufferInfo,
    op: impl FnOnce(CryptoBuffer) -> Result<CryptoBuffer, TlsError>,
) -> Result<(), TlsError> {
    let buf = CryptoBuffer::wrap_with_pos(&mut buffer[info.record_offset..], info.pos);

    match op(buf) {
        Ok(buf) => {
            info.pos = buf.len();
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn close_record<'a, CipherSuite>(
    buffer: &'a mut [u8],
    info: &mut WriteBufferInfo,
    write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
) -> Result<&'a [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    const HEADER_SIZE: usize = 5;

    // Verify invariant.
    assert!(buffer.len() >= info.record_offset + info.pos);
    assert!(TLS_RECORD_OVERHEAD >= HEADER_SIZE);

    // See if there is insufficient space in the buffer to close the record.
    // Outside of a non-blocking context, this cannot happen since `::new`
    // verifies that the buffer space is large enough to fit at least some
    // data, and `append` ensures that enough space is left at the end.
    if buffer.len() - info.record_offset - info.pos < (TLS_RECORD_OVERHEAD - HEADER_SIZE) {
        return Err(TlsError::WouldBlock);
    }

    let header = info.current_header.take().unwrap();
    with_buffer(buffer, info, |mut buf| {
        if !header.is_encrypted() {
            return Ok(buf);
        }

        buf.push(header.trailer_content_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;

        let mut buf = buf.offset(HEADER_SIZE);
        encrypt(write_key_schedule, &mut buf)?;
        Ok(buf.rewind())
    })?;
    let [upper, lower] = ((info.pos - HEADER_SIZE) as u16).to_be_bytes();

    buffer[info.record_offset + 3] = upper;
    buffer[info.record_offset + 4] = lower;

    let slice = &buffer[info.record_offset..info.record_offset + info.pos];

    // In non-blocking mode, multiple records can be accumulated and will
    // eventually be flushed by the caller; in blocking/async mode, no accumulation
    // happens and the caller of `close_record` is responsible to transmit the
    // generated record.
    if info.nonblocking {
        info.record_offset += info.pos;
    }
    info.pos = 0;
    info.current_header = None;

    Ok(slice)
}

fn write_record<'a, CipherSuite>(
    buffer: &'a mut [u8],
    info: &mut WriteBufferInfo,
    record: &ClientRecord<CipherSuite>,
    write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    read_key_schedule: Option<&mut ReadKeySchedule<CipherSuite>>,
) -> Result<&'a [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if info.current_header.is_some() {
        return Err(TlsError::InternalError);
    }

    // In a non-blocking context, starting a record could fail due to insufficient buffer space.
    start_record(buffer, info, record.header())?;

    // FIXME: these records can be longer than what we have reserved.
    // At this point, we are committed - we can't bail out with
    // `TlsError::WouldBlock` if the buffer is too small.

    with_buffer(buffer, info, |buf| {
        let mut buf = buf.forward();
        record.encode_payload(&mut buf)?;

        let transcript = read_key_schedule
            .ok_or(TlsError::InternalError)?
            .transcript_hash();

        record.finish_record(&mut buf, transcript, write_key_schedule)?;
        Ok(buf.rewind())
    })?;
    close_record(buffer, info, write_key_schedule)
        .inspect_err(|e| assert!(!matches!(e, TlsError::WouldBlock)))
}

#[cfg(test)]
mod nonblocking_test {
    use super::{WriteBuffer, WriteBufferInfo};
    use crate::Aes128GcmSha256;
    use crate::TlsError;
    use crate::config::TLS_RECORD_OVERHEAD;
    use crate::key_schedule::KeySchedule;
    use crate::record::ClientRecordHeader;

    #[test]
    fn empty_info_has_no_pending_bytes() {
        assert_eq!(WriteBufferInfo::empty().pending_bytes(), 0);
    }

    #[test]
    fn start_record_would_block_without_room_for_overhead() {
        let mut buffer = [0u8; TLS_RECORD_OVERHEAD - 1];
        let mut wb = WriteBuffer::from_info(&mut buffer, WriteBufferInfo::empty());
        assert!(matches!(
            wb.start_record(ClientRecordHeader::ApplicationData),
            Err(TlsError::WouldBlock)
        ));
    }

    #[test]
    fn accounting_is_relative_to_record_offset() {
        // Simulate one already-closed record occupying the front of the buffer.
        const RECORD_OFFSET: usize = 200;
        let mut buffer = [0u8; 1024];
        let info = WriteBufferInfo {
            pos: 0,
            record_offset: RECORD_OFFSET,
            current_header: None,
            nonblocking: true,
        };
        let mut wb = WriteBuffer::from_info(&mut buffer, info);

        assert_eq!(
            wb.reborrow().space(),
            1024 - TLS_RECORD_OVERHEAD - RECORD_OFFSET
        );
        assert!(!wb.is_full());
        assert!(wb.is_empty()); // no open record yet

        wb.start_record(ClientRecordHeader::ApplicationData)
            .unwrap();
        assert!(wb.contains(ClientRecordHeader::ApplicationData));
        let header_len = wb.reborrow().len(); // header bytes written by start_record
        assert_eq!(wb.append(&[0xAB; 50]), 50);
        assert_eq!(wb.reborrow().len(), header_len + 50);
    }

    #[test]
    fn into_info_reports_closed_bytes_and_resets_record_offset() {
        let mut buffer = [0u8; 1024];
        // 200 bytes of closed records, plus an open record of 40 bytes.
        let info = WriteBufferInfo {
            pos: 40,
            record_offset: 200,
            current_header: Some(ClientRecordHeader::ApplicationData),
            nonblocking: true,
        };
        let wb = WriteBuffer::from_info(&mut buffer, info);
        let (tx_complete, persisted) = wb.into_info();

        // Closed records are reported as transmittable...
        assert_eq!(tx_complete, 200);
        // ...and the persisted info carries the open record forward with record_offset zeroed.
        assert_eq!(persisted.record_offset, 0);
        assert_eq!(persisted.pos, 40);
        assert_eq!(persisted.pending_bytes(), 40);
        assert!(matches!(
            persisted.current_header,
            Some(ClientRecordHeader::ApplicationData)
        ));
    }

    /// Regression test for the blocking/async buffer-space leak: closing a record
    /// in blocking mode must NOT advance `record_offset` (the record is transmitted
    /// immediately and the buffer reused), whereas non-blocking mode retains it.
    #[test]
    fn blocking_close_does_not_accumulate_record_offset() {
        let mut ks = KeySchedule::<Aes128GcmSha256>::new();
        // A non-encrypted handshake header lets `close_record` run without real keys.
        let header = ClientRecordHeader::Handshake(false);

        // Blocking/async mode (`new`): record_offset stays 0 after a close.
        let mut blocking = [0u8; 1024];
        let mut wb = WriteBuffer::new(&mut blocking);
        wb.start_record(header).unwrap();
        wb.append(&[0xAB; 50]);
        wb.close_record(ks.write_state()).unwrap();
        assert_eq!(wb.into_info().0, 0, "blocking mode must not accumulate");

        // Non-blocking mode (`from_info`/`empty`): the closed record is retained.
        let mut nonblocking = [0u8; 1024];
        let mut wb = WriteBuffer::from_info(&mut nonblocking, WriteBufferInfo::empty());
        wb.start_record(header).unwrap();
        wb.append(&[0xAB; 50]);
        wb.close_record(ks.write_state()).unwrap();
        assert!(
            wb.into_info().0 > 0,
            "non-blocking mode must retain the record"
        );
    }
}
