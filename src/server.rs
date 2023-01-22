use std::{
    error::Error,
    mem::size_of,
    net::{Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use bytes::Bytes;
use clap::Parser;
use mimalloc::MiMalloc;
use quic_test::{setup_logging, Size, QUIC_PROTO};
use quinn::{
    Connecting, Endpoint, RecvStream,
};
use rouille::Response;
use rustls::{PrivateKey, Certificate, ServerConfig};
use tokio::{fs::File, io::{AsyncWriteExt, BufWriter}, runtime::Runtime};
use tracing::{error, info, info_span, trace, warn};
use tracing_futures::Instrument;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let options = CliOpt::parse();

    if options.ports.len() < 2 {
        error!("At least two ports must be provided");
        std::process::exit(-1);
    }

    setup_logging(options.verbose)?;

    let (key, certs) = setup_certs(options.key, options.cert)?;

    trace!("Loaded/created certificate");

    let mut server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    server_config.alpn_protocols = vec![ QUIC_PROTO.to_vec() ];
    if options.keylog {
        server_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    trace!("Loaded server config");

    let out_dir = Arc::new(options.output_dir);
    if !out_dir.exists() {
        std::fs::create_dir_all(&*out_dir)?;
        info!("Created output direction: {:?}", *out_dir);
    }

    let servers = Mutex::new(
        options
            .ports
            .iter()
            .skip(1)
            .copied()
            .enumerate()
            .map(|(index, port)| {
                let connection_count = Arc::new(AtomicUsize::new(0));

                let runtime = spawn_socket(
                    index,
                    options.count,
                    port,
                    Arc::clone(&out_dir),
                    Arc::clone(&connection_count),
                    server_config.clone(),
                )?;

                let socket = Socket {
                    port,
                    connection_count,
                    _runtime: runtime,
                };

                Ok::<_, Box<dyn Error + Send + Sync>>(socket)
            })
            .collect::<Result<Vec<Socket>, _>>()?,
    );

    trace!("Spawned sockets");

    rouille::start_server(
        &SocketAddr::from((Ipv6Addr::LOCALHOST, options.ports[0])),
        move |_| {
            let mut servers = servers.lock().unwrap();

            servers.sort_by(|a, b| {
                a.connection_count
                    .load(Ordering::Relaxed)
                    .cmp(&b.connection_count.load(Ordering::Relaxed))
            });

            servers[0].connection_count.fetch_add(1, Ordering::Relaxed);

            Response::text(format!("{}", servers[0].port))
        },
    );
}

struct Socket {
    port: u16,
    connection_count: Arc<AtomicUsize>,
    _runtime: Runtime,
}

fn spawn_socket(
    index: usize,
    count: usize,
    port: u16,
    out_dir: Arc<PathBuf>,
    connection_count: Arc<AtomicUsize>,
    server_config: ServerConfig,
) -> Result<Runtime, Box<dyn Error + Send + Sync>> {
    let span = info_span!("socket", index = %index, port = %port);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name(format!("pool-{}", index))
        .worker_threads(count)
        .enable_all()
        .build()?;

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_config));
    runtime.spawn(
            async move {
                let endpoint = Endpoint::server(server_config, format!("[::]:{port}").parse()?)?;

                info!("Listening on [::1]:{}", port);
                trace!("Created the endpoint");

                while let Some(conn) = endpoint.accept().await {
                    info!("New connection: {:?}", conn.remote_address());

                    tokio::spawn(handle_connection(
                        out_dir.clone(),
                        connection_count.clone(),
                        conn,
                    ));
                }

                Ok::<(), Box<dyn Error + Send + Sync>>(())
            }
            .instrument(span),
        );

    Ok(runtime)
}

async fn handle_connection(
    out_dir: Arc<PathBuf>,
    connection_count: Arc<AtomicUsize>,
    connecting: Connecting,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let span = info_span!("connection", remote = %connecting.remote_address());
    let connection = connecting.await?;

    connection_count.fetch_add(1, Ordering::Relaxed);

    async {
        info!("Established");

        while let Ok(stream) = connection.accept_uni().await {
            tokio::spawn(
                handle_transfer(out_dir.clone(), stream).instrument(info_span!("transfer")),
            );
        }

        Ok(())
    }
    .instrument(span)
    .await
}

async fn handle_transfer(
    out_dir: Arc<PathBuf>,
    mut recv: RecvStream,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Reads the file name's length
    let mut file_name_length = [0; size_of::<u64>()];
    recv.read_exact(&mut file_name_length).await?;
    let file_name_length = u64::from_le_bytes(file_name_length) as usize;

    // Reads the file name
    let mut file_name = vec![0_u8; file_name_length];
    recv.read_exact(&mut file_name).await?;
    let file_name = String::from_utf8(file_name)?;

    // Reads the file length
    let mut file_length = [0; size_of::<u64>()];
    recv.read_exact(&mut file_length).await?;
    let file_length = u64::from_le_bytes(file_length) as usize;

    info!(
        "Transfering `{}` of size {}",
        file_name,
        Size::from(file_length)
    );
    let mut recv_len = 0;

    let file = File::create(out_dir.join(file_name)).await?;

    let start = Instant::now();

    let mut writer = BufWriter::new(file);

    while let Some(chunk) = recv.read_chunk(std::usize::MAX, true).await? {
        if chunk.bytes.len() == 0 {
            continue;
        }

        recv_len += chunk.bytes.len();

        writer.write_all(&chunk.bytes).await?;
        trace!("Wrote {} bytes", chunk.bytes.len());
    }

    let end = start.elapsed();

    if recv_len < file_length {
        error!("Did not receive the entire file!");
    }

    info!(
        "Finished transfering in {:?}, average speed: {} MiB/s",
        end,
        (file_length as f64 / (1024.0 * 1024.0)) / end.as_secs_f64()
    );

    Ok(())
}

fn setup_certs(
    key_path: Option<PathBuf>,
    cert_path: Option<PathBuf>,
) -> Result<(PrivateKey, Vec<Certificate>), anyhow::Error> {
    let (key, cert) = if let (Some(key_path), Some(cert_path)) = (&key_path, &cert_path) {
        (std::fs::read(key_path)?, std::fs::read(cert_path)?)
    } else {
        warn!("Using self-signed certificated");

        let cert = rcgen::generate_simple_self_signed(vec![ "localhost".to_owned() ])?;

        let key = cert.serialize_private_key_der();
        let cert = cert.serialize_der()?;

        std::fs::write(&PathBuf::from("key.der"), &key)?;
        std::fs::write(&PathBuf::from("cert.der"), &cert)?;

        (key, cert)
    };

    let key = if key_path.map_or(true, |p| p.extension().map_or(false, |x| x == "der")) {
        PrivateKey(key)
    } else {
        let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)?;
        match pkcs8.into_iter().next() {
            Some(x) => rustls::PrivateKey(x),
            None => {
                let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)?;
                match rsa.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        anyhow::bail!("no private keys found");
                    }
                }
            }
        }
    };

    let cert_chain = if cert_path.map_or(true, |c| c.extension().map_or(false, |x| x == "der")){
        vec![rustls::Certificate(cert)]
    } else {
        rustls_pemfile::certs(&mut &*cert)?
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    Ok((key, cert_chain))
}

/// QUICCtest server CLI options
#[derive(Parser, Clone)]
#[command(version = "0.1", author = "Dherse <seb@dherse.dev>")]
pub struct CliOpt {
    /// A level of verbosity (not present = error only, -v = warnings, -vv = info, -vvv = debug, -vvvv = trace)
    #[clap(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// TLS private key in PEM format, requires a `cert`
    #[clap(short, long, requires = "cert")]
    pub key: Option<PathBuf>,

    /// TLS certificate in PEM format, requires a `key`
    #[clap(short, long, requires = "key")]
    pub cert: Option<PathBuf>,

    /// The number of threads per socket.
    #[clap(short = 't', long, default_value = "2")]
    pub count: usize,

    /// Enables stateless retries
    #[clap(long)]
    pub stateless_retry: bool,

    /// Keylog the keys of the server
    #[clap(long, short = 'l')]
    pub keylog: bool,

    /// Path to the directory in which to write the output files
    pub output_dir: PathBuf,

    /// The ports of the server, must be at least two.
    pub ports: Vec<u16>,
}
