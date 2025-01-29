#![macro_use]
use embedded_tls::nonblocking::TlsConnection;
use embedded_tls::nonblocking::Workbuf;
use embedded_tls::TlsCipherSuite;
use embedded_tls::TlsError;
use log::info;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Once;

mod tlsserver;

static LOG_INIT: Once = Once::new();
static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

fn init_log() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

fn setup() -> SocketAddr {
    use mio::net::TcpListener;
    init_log();
    INIT.call_once(|| {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        std::thread::spawn(move || {
            tlsserver::run(listener);
        });
        unsafe { ADDR.replace(addr) };
    });
    unsafe { ADDR.unwrap() }
}

const BUFFER_SIZE: usize = 16384;

/// A very simple connection buffer.
struct Buffer {
    receive_buffer: [u8; BUFFER_SIZE],
    receive_buffer_rptr: usize,
    receive_buffer_wptr: usize,

    transmit_buffer: [u8; BUFFER_SIZE],
    transmit_buffer_wptr: usize,
    transmit_buffer_rptr: usize,

    rx_limit: usize,
}

impl Buffer {
    /// Create an empty buffer.
    pub fn new() -> Self {
        Self {
            receive_buffer: [0; BUFFER_SIZE],
            receive_buffer_rptr: 0,
            receive_buffer_wptr: 0,
            transmit_buffer: [0; BUFFER_SIZE],
            transmit_buffer_wptr: 0,
            transmit_buffer_rptr: 0,
            rx_limit: usize::MAX,
        }
    }

    /// Creates a TLS workbuf based on the currently valid data, and calls `f`
    /// with it. Finally, the buffer pointers will be adjusted to the consumed
    /// and submitted RX/TX bytes.
    ///
    /// Both RX and TX buffers are re-presented on the next call (if not consumed/submitted) so
    /// in-place encryption and decryption can be used.
    pub fn call_tls<CipherSuite, F, R>(&mut self, tls: &mut TlsConnection<CipherSuite>, f: F) -> R
    where
        CipherSuite: TlsCipherSuite + 'static,
        F: FnOnce(&mut TlsConnection<CipherSuite>, &mut Workbuf) -> R,
    {
        // RX: All received but non-consumed RX bytes
        // TX: All (initially unused) bytes until the end of the buffer.
        let mut workbuf = tls.take_workbuf(
            &mut self.receive_buffer[self.receive_buffer_rptr..self.receive_buffer_wptr],
            &mut self.transmit_buffer[self.transmit_buffer_wptr..],
        );

        // Call the closure.
        let res = f(tls, &mut workbuf);

        // Upon completion, the number of consumed RX bytes will be dropped from
        // the begin of the buffer by adjusting `receive_buf_rptr`, and the number
        // of submitted TX bytes will be marked as pending by adjusting
        // `transmit_buf_wptr`.

        let (rx_used, tx_complete) = tls.put_workbuf(workbuf);

        self.receive_buffer_rptr += rx_used;
        self.transmit_buffer_wptr += tx_complete;

        res
    }

    /// Attempts to transmit submitted TX data to the given TCP stream. The
    /// operation can block.
    pub fn try_transmit(&mut self, stream: &mut TcpStream) {
        let tx = stream
            .write(&self.transmit_buffer[self.transmit_buffer_rptr..self.transmit_buffer_wptr])
            .expect("tcp write failed");
        if tx != 0 {
            info!(">> {tx} TX");
        }
        self.transmit_buffer_rptr += tx;
    }

    /// Attempts to read RX data from the given TCP stream. The operation can be
    /// chosen to be blocking or non-blocking.
    pub fn try_receive(&mut self, stream: &mut TcpStream, blocking: bool) {
        stream
            .set_nonblocking(!blocking)
            .expect("set nonblocking failed");

        // Consider an optional read limit
        let end_rx_buffer =
            (self.receive_buffer_wptr.saturating_add(self.rx_limit)).min(self.receive_buffer.len());

        let rx =
            match stream.read(&mut self.receive_buffer[self.receive_buffer_wptr..end_rx_buffer]) {
                Ok(rx) => rx,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                Err(e) => panic!("TCP read failed {e:?}"),
            };
        if rx != 0 {
            info!(">> {rx} RX");
        }
        self.receive_buffer_wptr += rx;

        // Default back to blocking.
        stream
            .set_nonblocking(false)
            .expect("set nonblocking failed");
    }

    /// Like `call_tls`, but retries after handling TCP data when
    /// `TlsError::WouldBlock` is returned. Other return values are passed
    /// through.
    pub fn retry_blocking<CipherSuite, F, R>(
        &mut self,
        tls: &mut TlsConnection<CipherSuite>,
        stream: &mut TcpStream,
        mut f: F,
    ) -> Result<R, TlsError>
    where
        CipherSuite: TlsCipherSuite + 'static,
        F: FnMut(&mut TlsConnection<CipherSuite>, &mut Workbuf) -> Result<R, TlsError>,
    {
        loop {
            let res = self.call_tls(tls, |tls, workbuf| f(tls, workbuf));
            match res {
                Err(TlsError::WouldBlock) => {
                    self.optimize();
                    self.try_transmit(stream);
                    self.try_receive(stream, true);
                }
                other => return other,
            }
        }
    }

    /// Rotates the buffer to drop unused data. This operation is not efficient.
    pub fn optimize(&mut self) {
        self.receive_buffer.rotate_left(self.receive_buffer_rptr);
        self.receive_buffer_wptr -= self.receive_buffer_rptr;
        self.receive_buffer_rptr = 0;

        self.transmit_buffer.rotate_left(self.transmit_buffer_rptr);
        self.transmit_buffer_wptr -= self.transmit_buffer_rptr;
        self.transmit_buffer_rptr = 0;
    }
}

#[test]
fn test_nonblocking_ping() {
    use embedded_tls::nonblocking::*;
    use std::net::TcpStream;

    let addr = setup();
    let pem = include_str!("data/ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);
    let mut stream = TcpStream::connect(addr).expect("error connecting to server");

    log::info!("Connected");

    let mut buf = Buffer::new();

    let config = TlsConfig::new()
        .with_ca(Certificate::X509(&der[..]))
        .with_server_name("localhost");

    let mut context = TlsContext::new(&config, UnsecureProvider::new::<Aes128GcmSha256>(OsRng));

    let mut tls: TlsConnection<Aes128GcmSha256> = TlsConnection::new();

    while !tls.opened {
        info!("not opened, continue handshake.");
        buf.retry_blocking(&mut tls, &mut stream, |tls, workbuf| {
            tls.continue_open(&mut context, workbuf)
        })
        .expect("TLS open failed");
    }

    log::info!("Established");

    let written = buf
        .retry_blocking(&mut tls, &mut stream, |tls, workbuf| {
            tls.write(b"ping", workbuf)
        })
        .expect("error writing data");

    assert_eq!(written, 4);

    buf.retry_blocking(&mut tls, &mut stream, |tls, workbuf| tls.flush(workbuf))
        .expect("error flushing data");

    // Make sure reading into a 0 length buffer doesn't loop
    let mut rx_buf = [0; 0];
    let sz = buf
        .retry_blocking(&mut tls, &mut stream, |tls, workbuf| {
            tls.read(workbuf, &mut rx_buf)
        })
        .expect("error reading data");

    assert_eq!(sz, 0);

    let mut rx_buf = [0; 4096];
    let sz = buf
        .retry_blocking(&mut tls, &mut stream, |tls, workbuf| {
            tls.read(workbuf, &mut rx_buf)
        })
        .expect("error reading data");

    assert_eq!(4, sz);
    assert_eq!(b"ping", &rx_buf[..sz]);
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    // Test that embedded-tls doesn't block if the buffer is empty.
    let mut rx_buf = [0; 0];
    let sz = buf
        .retry_blocking(&mut tls, &mut stream, |tls, workbuf| {
            tls.read(workbuf, &mut rx_buf)
        })
        .expect("error reading data");

    assert_eq!(sz, 0);

    // Exercise full buffer behavior by keeping to send data.

    let mut total_rx = 0;
    let mut total_tx = 0;
    const BYTES_TO_SEND: usize = 512 * 1024;
    let mut tx_was_blocked = false;

    while total_rx < BYTES_TO_SEND {
        let buffer = [0; 1000];
        let bytes_to_send = (BYTES_TO_SEND - total_tx).min(buffer.len());
        if bytes_to_send != 0 {
            let written = buf
                .retry_blocking(&mut tls, &mut stream, |tls, workbuf| {
                    tls.write(&buffer[0..bytes_to_send], workbuf)
                })
                .expect("error writing data");
            total_tx += written;

            assert!(written != 0);

            // Was this a partial write?
            tx_was_blocked |= written != bytes_to_send;

            if total_tx == BYTES_TO_SEND {
                let _ = buf
                    .retry_blocking(&mut tls, &mut stream, |tls, workbuf| tls.flush(workbuf))
                    .expect("error writing data");
            }
        }

        // Ensure we also exercise all various phases of empty receive buffers
        // by limiting RX to 1 byte per attempt. This is quite slow so only do it for the last 10%.
        if total_rx > BYTES_TO_SEND * 9 / 10 {
            buf.rx_limit = 1;
        }

        buf.optimize();
        buf.try_receive(&mut stream, false);
        buf.try_transmit(&mut stream);

        while {
            let mut rx_buf = [0; 4096];

            let rx = match buf.call_tls(&mut tls, |tls, workbuf| tls.read(workbuf, &mut rx_buf)) {
                Ok(rx) => Ok(rx),
                Err(TlsError::WouldBlock) => Ok(0),
                other => other,
            }
            .expect("error reading data");

            total_rx += rx;

            rx != 0
        } {}
    }

    // Ensure we at least once ran into a TX partial write.
    assert!(tx_was_blocked);

    let mut tx_buf = [0; 1000];
    let mut rx_buf = [0; 1000];

    for pktsize in 0..tx_buf.len() {
        OsRng.fill_bytes(&mut tx_buf);

        let written = buf
            .retry_blocking(&mut tls, &mut stream, |tls, workbuf| {
                tls.write(&tx_buf[0..pktsize], workbuf)
            })
            .expect("error writing data");

        assert_eq!(written, pktsize);
        buf.retry_blocking(&mut tls, &mut stream, |tls, workbuf| tls.flush(workbuf))
            .expect("error flushing data");

        let sz = buf
            .retry_blocking(&mut tls, &mut stream, |tls, workbuf| {
                tls.read(workbuf, &mut rx_buf[0..pktsize])
            })
            .expect("error reading data");
        assert_eq!(sz, pktsize);
        assert_eq!(tx_buf[0..pktsize], rx_buf[0..pktsize]);
    }

    buf.retry_blocking(&mut tls, &mut stream, |tls, workbuf| tls.close(workbuf))
        .expect("error closing session data");

    buf.try_transmit(&mut stream);
}
