use std::{error::Error, net::IpAddr, path::PathBuf, time::Instant};

use clap::{AppSettings, Clap};
use mimalloc::MiMalloc;
use quicc_test::{setup_logging, QUIC_PROTO};
use quinn::{Certificate, ClientConfigBuilder, Endpoint};
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{info, trace};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let options = CliOpt::parse();

    setup_logging(options.verbose)?;

    let cert = setup_cert(options.cert).await?;

    let mut client_config = ClientConfigBuilder::default();
    client_config
        .add_certificate_authority(cert)?
        .protocols(QUIC_PROTO);

    if options.keylog {
        client_config.enable_keylog();
    }

    let mut endpoint = Endpoint::builder();
    endpoint.default_client_config(client_config.build());

    let (endpoint, _) = endpoint.bind(&"[::]:0".parse()?)?;

    trace!("Getting port from http://[{}]:{}/", options.ip, options.port);

    let resp = reqwest::get(format!("http://[{}]:{}/", options.ip, options.port)).await?.text().await?.parse()?;

    trace!("Got port {}", resp);

    let new_conn = endpoint
        .connect(&(options.ip, resp).into(), "localhost")?
        .await?;

    let mut send = new_conn.connection.open_uni().await?;

    let mut file = File::open(&options.file).await?;
    let name = options
        .transfer_name
        .as_ref()
        .map(|s| s as &str)
        .unwrap_or_else(|| {
            options
                .file
                .file_name()
                .expect("No file name")
                .to_str()
                .expect("Failed to convert file name")
        });
    let len = file.metadata().await?.len();

    {
        let file_name_len = (name.len() as u64).to_le_bytes();
        send.write_all(&file_name_len).await?;
    }

    {
        send.write_all(name.as_bytes()).await?;
    }

    {
        let file_len = len.to_le_bytes();
        send.write_all(&file_len).await?;
    }

    let len = len as usize;

    let mut buf = Vec::with_capacity(len);
    file.read_to_end(&mut buf).await?;

    let start = Instant::now();

    let mut send_len = 0;
    loop {
        let n = send.write(&buf[send_len..]).await?;
        send_len += n;

        if send_len == len {
            break;
        }
    }

    let end = start.elapsed();

    send.finish().await?;

    info!(
        "Finished transfering in {:?}, average speed: {} MiB/s",
        end,
        (len as f64 / (1024.0 * 1024.0)) / end.as_secs_f64()
    );

    Ok(())
}

async fn setup_cert(
    cert_path: PathBuf,
) -> Result<Certificate, Box<dyn Error + Send + Sync + 'static>> {
    Ok(Certificate::from_der(&tokio::fs::read(cert_path).await?)?)
}

/// QUICCtest client CLI options
#[derive(Clap, Clone)]
#[clap(version = "0.1", author = "Dherse <seb@dherse.dev>")]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct CliOpt {
    /// A level of verbosity (not present = error only, -v = warnings, -vv = info, -vvv = debug, -vvvv = trace)
    #[clap(short, long, parse(from_occurrences))]
    pub verbose: u8,

    /// Keylog the keys of the server
    #[clap(long, short = 'l')]
    pub keylog: bool,

    /// TLS certificate key in PEM format
    pub cert: PathBuf,

    /// Path to the file to be sent
    pub file: PathBuf,

    /// IP address to send to
    pub ip: IpAddr,

    /// The port of the server
    pub port: u16,

    /// The name of the transfered file
    pub transfer_name: Option<String>,
}
