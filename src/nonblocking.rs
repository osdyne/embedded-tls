use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::connection::{decrypt_record, Handshake, State};
use crate::key_schedule::KeySchedule;
use crate::key_schedule::WriteKeySchedule;
use crate::read_buffer::ReadBuffer;
use crate::record::{ClientRecord, ClientRecordHeader};
use crate::record_reader::RecordReader;
use crate::write_buffer::{WriteBuffer, WriteBufferInfo};

pub use crate::config::*;
pub use crate::TlsError;

/// Type representing a TLS connection. An instance of this type can be used to
/// establish a TLS connection, write and read encrypted data over this
/// connection, and closing to free up the underlying resources.
///
/// In this non-blocking variant, the transport itself is not part of this
/// object; at every call that requires received data or produces transmit data,
/// a `Workbuf` object is required from the caller.
pub struct TlsConnection<CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    pub opened: bool,
    key_schedule: KeySchedule<CipherSuite>,
    decrypted: DecryptedBufferInfo,
    state: State,
    handshake: Handshake<CipherSuite>,
    write_buffer_info: Option<WriteBufferInfo>,
}

/// A `Workbuf` is the representation of the currently pending TLS frames, both
/// on the receive and transmit side. Typically, a `Workbuf` is obtained
/// directly on top of the TCP receive and send buffer using
/// `TlsConnection::take_workbuf`.
pub struct Workbuf<'a> {
    record_reader: RecordReader<'a>,
    write_buffer: WriteBuffer<'a>,
}

impl<'a> Workbuf<'a> {
    /// Create a workbuf from a supplied read and write buffer, and meta-information
    /// that need to be retained.
    pub fn new(
        write_buffer_info: WriteBufferInfo,
        read_buffer: &'a mut [u8],
        already_decoded: usize,
        write_buffer: &'a mut [u8],
    ) -> Self {
        Self {
            record_reader: RecordReader::with_data(read_buffer, already_decoded),
            write_buffer: WriteBuffer::from_info(write_buffer, write_buffer_info),
        }
    }

    // Disassemble a work buffer; returns
    // - the number of used received bytes (that must not be re-presented next time),
    // - the number of completed TX bytes (that must not be re-presented next time),
    // - the remaining pending bytes, that _must_ be represented next time.
    pub fn disassemble(self) -> (usize, usize, WriteBufferInfo) {
        let (tx_complete, info) = self.write_buffer.into_info();

        (
            self.record_reader.buf.len() - self.record_reader.pending,
            tx_complete,
            info,
        )
    }

    // Returns the number of consumed RX bytes that must not be presented as a
    // workbuf again (i.e. must be discarded from the buffer).
    pub fn rx_used(&mut self) -> usize {
        self.record_reader.buf.len() - self.record_reader.pending
    }

    // Returns the number of submitted TX bytes that must not be presented as a
    // workbuf again (i.e. must be sent to the remote side).
    pub fn tx_used(&self) -> usize {
        self.write_buffer.len()
    }
}

impl<CipherSuite> TlsConnection<CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Create a new TLS connection for use in a non-blocking scenario.
    pub fn new() -> Self {
        Self {
            opened: false,
            key_schedule: KeySchedule::new(),
            decrypted: DecryptedBufferInfo::default(),
            state: State::ClientHello,
            handshake: Handshake::new(),
            write_buffer_info: Some(WriteBufferInfo::empty()),
        }
    }

    /// Continues the TLS handshake with the supplied context.
    /// `Err(TlsError::WouldBlock)` is returned if more IO is necessary;
    /// otherwise `Ok(())` is returned and `opened` will be set to `true`.
    pub fn continue_open<Provider>(
        &mut self,
        context: &mut TlsContext<Provider>,
        workbuf: &mut Workbuf,
    ) -> Result<(), TlsError>
    where
        Provider: CryptoProvider<CipherSuite = CipherSuite>,
    {
        if let (Ok(verifier), Some(server_name)) = (
            context.crypto_provider.verifier(),
            context.config.server_name,
        ) {
            verifier.set_hostname_verification(server_name)?;
        }

        while self.state != State::ApplicationData {
            let next_state = self.state.process_nonblocking(
                &mut self.handshake,
                &mut workbuf.record_reader,
                &mut workbuf.write_buffer,
                &mut self.key_schedule,
                context.config,
                &mut context.crypto_provider,
            )?;

            trace!("State {:?} -> {:?}", self.state, next_state);
            self.state = next_state;
        }
        self.opened = true;

        Ok(())
    }

    /// Encrypt and send the provided slice over the connection. The connection
    /// must be opened before writing.
    ///
    /// Writing can, but doesn't have to, finalize a TLS record. Only complete
    /// TLS records can be transmitted. [`Self::flush()`] must be called to
    /// force the currently buffered TLS frame to be closed if the data needs to
    /// be sent.
    ///
    /// Returns the number of bytes written (which can be less than the
    /// requested buffer), or `Err(TlsError::WouldBlock)` if there is no buffer
    /// space to even start a partial write.
    pub fn write(&mut self, buf: &[u8], workbuf: &mut Workbuf) -> Result<usize, TlsError> {
        if self.opened {
            if !workbuf
                .write_buffer
                .contains(ClientRecordHeader::ApplicationData)
            {
                // `.append` doesn't fill the buffer more so the flush can never
                // run out of buffer space.
                self.flush(workbuf)?;

                // `.start_record` may return `TlsError::WouldBlock`. This this
                // case, we have closed the record, but are still in a valid
                // state for the caller to retry.
                workbuf
                    .write_buffer
                    .start_record(ClientRecordHeader::ApplicationData)?;
            }

            // `.append` stops writing data if this would prevent the transmit
            // buffer from being flushed; in this case, a partial write happens.
            let buffered = workbuf.write_buffer.append(buf);

            // If the buffer is full now, call `.flush`. This will also close
            // th4e record and allow the current buffer to be transmitted,
            // eventually making more space for more transmit data.
            if workbuf.write_buffer.is_full() {
                // Since at this point we can be sure that:
                // - We're currently in an open ApplicationData record,
                // - `.append` left enough space for closing of the record, the
                // following `.flush` would never run out of buffer space.
                self.flush(workbuf)?;
            }

            Ok(buffered)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    /// Force all previously written, buffered bytes to be encoded into a tls record, so that the
    /// TLS record is ready for transmission.
    pub fn flush(&mut self, workbuf: &mut Workbuf) -> Result<(), TlsError> {
        if !workbuf.write_buffer.is_empty() {
            let key_schedule: &mut WriteKeySchedule<CipherSuite> = self.key_schedule.write_state();
            let _ = workbuf.write_buffer.close_record(key_schedule)?;

            key_schedule.increment_counter();
        }

        Ok(())
    }

    fn create_read_buffer<'a, 'b, 'c>(
        &'a mut self,
        record_reader: &'c mut RecordReader<'b>,
    ) -> ReadBuffer<'c>
    where
        'a: 'c,
        'b: 'c,
    {
        self.decrypted.create_read_buffer(record_reader.buf)
    }

    /// Read and decrypt data filling the provided slice.
    pub fn read<'a, 'b>(
        &mut self,
        workbuf: &'a mut Workbuf<'b>,
        buf: &mut [u8],
    ) -> Result<usize, TlsError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = {
            let mut buffer = self.read_buffered(workbuf)?;

            let len = buffer.pop_into(buf);
            trace!("Copied {} bytes", len);
            len
        };

        Ok(len)
    }

    /// Reads buffered data. If nothing is in memory, it'll attempt to decode
    /// more TLS records and process them.
    pub fn read_buffered<'a, 'b, 'c>(
        &'a mut self,
        workbuf: &'c mut Workbuf<'b>,
    ) -> Result<ReadBuffer<'c>, TlsError>
    where
        'a: 'c,
        'b: 'c,
    {
        if self.opened {
            // If `self.decrypted.is_empty`, then there is no pending block of
            // plaintext data. Process TLS records until there is one (or we run
            // out of TLS data.)
            while self.decrypted.is_empty() {
                let res = self.read_application_data(&mut workbuf.record_reader);
                res?;
            }

            Ok(self.create_read_buffer(&mut workbuf.record_reader))
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn read_application_data<'a>(
        &mut self,
        record_reader: &mut RecordReader,
    ) -> Result<(), TlsError> {
        assert!(self.decrypted.is_empty());
        let buf_ptr_range = record_reader.buf.as_ptr_range();
        let key_schedule = self.key_schedule.read_state();
        let record = record_reader.read_nonblocking(key_schedule)?;

        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: &mut self.opened,
        };
        decrypt_record(key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        })?;

        Ok(())
    }

    /// Create a workbuf from the passed in buffers (likely raw TCP window
    /// buffers). The RX side consiststs of 0..n bytes of an already
    /// decrypted TLS application data record (left over by a previous call),
    /// and 0..n bytes of additional received TLS data.
    pub fn take_workbuf<'a>(
        &mut self,
        read_buffer: &'a mut [u8],
        write_buffer: &'a mut [u8],
    ) -> Workbuf<'a> {
        let preserved_decrypted_data = self.decrypted.bytes_to_preserve();

        Workbuf::new(
            self.write_buffer_info.take().expect("no workbuf available"),
            read_buffer,
            preserved_decrypted_data,
            write_buffer,
        )
    }

    pub fn pending_write(&self) -> Option<usize> {
        self.write_buffer_info
            .as_ref()
            .map(|write_buffer_info| write_buffer_info.pending_bytes())
    }

    // The returned rx_used, tx_complete bytes shall NOT be re-presented in the next "take_workbuf"
    pub fn put_workbuf(&mut self, workbuf: Workbuf) -> (usize, usize) {
        let (rx_used, tx_complete, info) = workbuf.disassemble();
        self.write_buffer_info.replace(info);

        // On the RX side of the workbuf, we consumed 0..n TLS records.
        // However, the last TLS record could have been an application data record,
        // with data not yet consumed. As far as the record reader is concerned, that data is
        // already consumed, but we need to preserve it.

        let decrypted_data_to_preserve = self.decrypted.bytes_to_preserve();

        // Obviously, the preserved data must have been already consumed by the record reader.
        assert!(rx_used >= decrypted_data_to_preserve);

        let rx_bytes_to_drop = rx_used - decrypted_data_to_preserve;

        // Let the decrypted data buffer know that we are eliminating bytes from the buffer
        self.decrypted.drop_buffer_bytes(rx_bytes_to_drop);

        (rx_bytes_to_drop, tx_complete)
    }

    pub fn close<'b, 'c>(&mut self, workbuf: &'c mut Workbuf<'b>) -> Result<(), TlsError> {
        // Try to flush. If that fails, return.
        self.flush(workbuf)?;

        // Write close notification. If this fails, the counter is not increment so we can retry.
        let (write_key_schedule, read_key_schedule) = self.key_schedule.as_split();
        let _ = workbuf.write_buffer.write_record(
            &ClientRecord::close_notify(self.opened),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        self.key_schedule.write_state().increment_counter();

        self.flush(workbuf)?;

        Ok(())
    }
}
