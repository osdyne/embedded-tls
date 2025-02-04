use std::{
    ffi::{c_char, c_int, CString},
    net::SocketAddr,
};

extern "C" {
    fn gnutlsserver_run(port: c_int, privkey_file: *const c_char, certs_file: *const c_char) -> c_int;
}

pub fn setup() -> SocketAddr {
    let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();

    std::thread::spawn(move || {
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

        let res = unsafe { gnutlsserver_run(addr.port().into(), privkey_file.as_ptr(), certs_file.as_ptr()) };
        assert_eq!(0, res);
    });

    addr
}
