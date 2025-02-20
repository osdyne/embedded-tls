#[cfg(target_os = "unix")]
fn setup_gnutls() {
    pkg_config::Config::new()
        // gnutls version that added "record size limit"
        .atleast_version("3.6.4")
        .probe("gnutls")
        .unwrap();
    cc::Build::new()
        .opt_level(1)
        .file("tests/gnutlsserver.c")
        .compile("gnutlsserver");
    println!("cargo:rerun-if-changed=tests/gnutlsserver.c");
}

fn main() {
    #[cfg(target_os = "unix")]
    setup_gnutls();

    println!("cargo:rerun-if-changed=build.rs");
}
