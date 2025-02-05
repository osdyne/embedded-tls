use std::{
    ffi::{c_char, c_int, CString},
    net::SocketAddr,
};

extern "C" {
    fn gnutlsserver_init(port: c_int) -> c_int;
    fn gnutlsserver_run(listen_sd: c_int, privkey_file: *const c_char, certs_file: *const c_char) -> c_int;
}

/// Start a echoing gnutls server
///
/// Returns once it listens on a TCP port.
pub fn setup() -> SocketAddr {
    let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();

    let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

    let certs_file = CString::new(
        test_dir.join("data")
            .join("server-cert.pem")
            .into_os_string()
            .as_encoded_bytes())
        .unwrap();
    let privkey_file = CString::new(
        test_dir.join("data")
            .join("server-key.pem")
            .into_os_string()
            .as_encoded_bytes())
        .unwrap();

    let listen_sd = unsafe { gnutlsserver_init(addr.port().into()) };
    assert!(listen_sd >= 0);

    std::thread::spawn(move || {
        let res = unsafe {
            gnutlsserver_run(listen_sd, privkey_file.as_ptr(), certs_file.as_ptr())
        };
        assert_eq!(0, res);
    });

    addr
}
