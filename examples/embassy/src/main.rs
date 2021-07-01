#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]
#![feature(min_type_alias_impl_trait)]
#![feature(impl_trait_in_bindings)]
#![allow(incomplete_features)]

use clap::{AppSettings, Clap};
use core::future::Future;
use drogue_tls::*;
use embassy::executor::Spawner;
use embassy::io::{AsyncBufReadExt, AsyncWriteExt};
use embassy::util::Forever;
use embassy_net::*;
use embassy_std::Executor;
use heapless::Vec;
use log::*;
use rand::rngs::OsRng;

mod tuntap;

use crate::tuntap::TunTapDevice;

static DEVICE: Forever<TunTapDevice> = Forever::new();
//static CONFIG: Forever<DhcpConfigurator> = Forever::new();
static CONFIG: Forever<StaticConfigurator> = Forever::new();
static NET_RESOURCES: Forever<StackResources<1, 2, 8>> = Forever::new();

#[derive(Clap)]
#[clap(version = "1.0")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    /// TAP device name
    #[clap(long, default_value = "tap0")]
    tap: String,
}

#[embassy::task]
async fn net_task() {
    embassy_net::run().await
}

#[embassy::task]
async fn main_task(spawner: Spawner) {
    let opts: Opts = Opts::parse();

    // Init network device
    let device = TunTapDevice::new(&opts.tap).unwrap();

    // Static IP configuration
    let config = StaticConfigurator::new(Config {
        address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 69, 2), 24),
        dns_servers: Vec::new(),
        gateway: Some(Ipv4Address::new(192, 168, 69, 1)),
    });

    // DHCP configruation
    // let config = DhcpConfigurator::new();

    let net_resources = StackResources::new();

    // Init network stack
    embassy_net::init(
        DEVICE.put(device),
        CONFIG.put(config),
        NET_RESOURCES.put(net_resources),
    );

    // Launch network task
    spawner.spawn(net_task()).unwrap();

    // Then we can use it!
    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];
    let mut socket = TcpSocket::new(&mut rx_buffer, &mut tx_buffer);

    socket.set_timeout(Some(embassy_net::SmolDuration::from_secs(10)));

    let remote_endpoint = (Ipv4Address::new(192, 168, 69, 100), 12345);
    info!("connecting to {:?}...", remote_endpoint);
    let r = socket.connect(remote_endpoint).await;
    if let Err(e) = r {
        warn!("connect error: {:?}", e);
        return;
    }
    info!("connected!");

    let tls_config: TlsConfig<Aes128GcmSha256> = TlsConfig::new().with_server_name("example.com");
    let mut tls: TlsConnection<OsRng, TcpSocket, Aes128GcmSha256, 16384> =
        TlsConnection::new(tls_config, OsRng, socket);

    tls.open().await.expect("error establishing TLS connection");

    tls.write(b"ping").await.expect("error writing data");

    let mut rx_buf = [0; 128];
    let sz = tls.read(&mut rx_buf[..]).await.expect("error reading data");

    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
}

#[no_mangle]
fn _embassy_rand(buf: &mut [u8]) {
    use rand_core::RngCore;
    OsRng.fill_bytes(buf);
}

static EXECUTOR: Forever<Executor> = Forever::new();

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module("async_io", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    let executor = EXECUTOR.put(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(main_task(spawner)).unwrap();
    });
}
