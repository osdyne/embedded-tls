#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![doc = include_str!("../README.md")]
#![allow(dead_code)]

/*!
# Example

```
use embedded_tls::*;
use embedded_io_adapters::tokio_1::FromTokio;
use rand::rngs::OsRng;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let stream = TcpStream::connect("http.sandbox.drogue.cloud:443").await.expect("error creating TCP connection");

    println!("TCP connection opened");
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new()
        .with_server_name("http.sandbox.drogue.cloud");
    let mut tls: TlsConnection<FromTokio<TcpStream>, Aes128GcmSha256> =
        TlsConnection::new(FromTokio::new(stream), &mut read_record_buffer, &mut write_record_buffer);

    // Allows disabling cert verification, in case you are using PSK and don't need it, or are just testing.
    // otherwise, use embedded_tls::webpki::CertVerifier, which only works on std for now.
    tls.open::<OsRng, NoVerify>(TlsContext::new(&config, &mut OsRng)).await.expect("error establishing TLS connection");

    println!("TLS session opened");
}
```
*/

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

use parse_buffer::ParseError;
pub mod alert;
mod application_data;
pub mod blocking;
mod buffer;
mod change_cipher_spec;
mod cipher_suites;
mod common;
mod config;
mod connection;
mod content_types;
mod crypto_engine;
mod extensions;
mod handshake;
mod key_schedule;
mod parse_buffer;
pub mod read_buffer;
mod record;
mod record_reader;
mod split;
mod write_buffer;

#[cfg(feature = "webpki")]
pub mod webpki;

mod asynch;
pub use asynch::*;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsError {
    ConnectionClosed,
    Unimplemented,
    MissingHandshake,
    HandshakeAborted(alert::AlertLevel, alert::AlertDescription),
    AbortHandshake(alert::AlertLevel, alert::AlertDescription),
    IoError,
    InternalError,
    InvalidRecord,
    UnknownContentType,
    InvalidNonceLength,
    InvalidTicketLength,
    UnknownExtensionType,
    InsufficientSpace,
    InvalidHandshake,
    InvalidCipherSuite,
    InvalidSignatureScheme,
    InvalidSignature,
    InvalidExtensionsLength,
    InvalidSessionIdLength,
    InvalidSupportedVersions,
    InvalidApplicationData,
    InvalidKeyShare,
    InvalidCertificate,
    InvalidCertificateEntry,
    InvalidCertificateRequest,
    UnableToInitializeCryptoEngine,
    ParseError(ParseError),
    OutOfMemory,
    CryptoError,
    EncodeError,
    DecodeError,
    Io(embedded_io::ErrorKind),
}

impl embedded_io::Error for TlsError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Io(k) => *k,
            _ => {
                error!("TLS error: {:?}", self);
                embedded_io::ErrorKind::Other
            }
        }
    }
}

#[cfg(feature = "std")]
mod stdlib {
    use crate::config::TlsClock;

    use std::time::SystemTime;
    impl TlsClock for SystemTime {
        fn now() -> Option<u64> {
            Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
        }
    }
}
