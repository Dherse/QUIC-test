use std::{
    error::Error,
    iter::once,
    mem::size_of,
    net::{Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use clap::{AppSettings, Clap};
use futures_util::StreamExt;
use mimalloc::MiMalloc;
use quicc_test::{setup_logging, Size, QUIC_PROTO};
use quinn::{
    Certificate, CertificateChain, Connecting, ConnectionError, Endpoint, PrivateKey, RecvStream,
    ServerConfigBuilder,
};
use rouille::Response;
use tokio::runtime::Runtime;
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

    let mut server_config = ServerConfigBuilder::default();
    server_config
        .certificate(certs, key)?
        .protocols(QUIC_PROTO)
        .use_stateless_retry(options.stateless_retry);

    if options.keylog {
        server_config.enable_keylog();
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
                    index,
                    port,
                    out_dir: Arc::clone(&out_dir),
                    connection_count,
                    runtime,
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

    Ok(())
}

struct Socket {
    index: usize,
    port: u16,
    out_dir: Arc<PathBuf>,
    connection_count: Arc<AtomicUsize>,
    runtime: Runtime,
}

fn spawn_socket(
    index: usize,
    count: usize,
    port: u16,
    out_dir: Arc<PathBuf>,
    connection_count: Arc<AtomicUsize>,
    server_config: ServerConfigBuilder,
) -> Result<Runtime, Box<dyn Error + Send + Sync>> {
    let span = info_span!("socket", index = %index, port = %port);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name(format!("pool-{}", index))
        .worker_threads(count)
        .enable_all()
        .build()?;

    runtime.spawn(
            async move {
                let mut endpoint = Endpoint::builder();
                endpoint.listen(server_config.build());

                let (_endpoint, mut incoming) =
                    endpoint.bind(&SocketAddr::from((Ipv6Addr::LOCALHOST, port)))?;

                info!("Listening on [::1]:{}", port);
                trace!("Created the endpoint");

                while let Some(conn) = incoming.next().await {
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
    let mut connection = connecting.await?;

    // connection_count.fetch_add(1, Ordering::Relaxed);

    async {
        info!("Established");

        while let Some(stream) = connection.uni_streams.next().await {
            let stream = match stream {
                Ok(s) => s,
                Err(ConnectionError::ApplicationClosed { .. }) => {
                    connection_count.fetch_sub(1, Ordering::Relaxed);
                    info!("Connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e.into());
                }
            };

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

    let mut out = Vec::with_capacity(file_length as usize);
    unsafe {
        out.set_len(file_length as usize);
    }

    let start = Instant::now();

    while let Some(len) = recv.read(&mut out[recv_len..]).await? {
        recv_len += len;
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

    // tokio::fs::write(out_dir.join(file_name), &out).await?;

    Ok(())
}

fn setup_certs(
    key_path: Option<PathBuf>,
    cert_path: Option<PathBuf>,
) -> Result<(PrivateKey, CertificateChain), Box<dyn Error + Send + Sync + 'static>> {
    let (key, cert) = if let (Some(key_path), Some(cert_path)) = (&key_path, &cert_path) {
        (std::fs::read(key_path)?, std::fs::read(cert_path)?)
    } else {
        warn!("Using self-signed certificated");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;

        let key = cert.serialize_private_key_der();
        let cert = cert.serialize_der()?;

        std::fs::write(&PathBuf::from("key.der"), &key)?;
        std::fs::write(&PathBuf::from("cert.der"), &cert)?;

        (key, cert)
    };

    let key = if key_path.map_or(true, |p| p.extension().map_or(false, |x| x == "der")) {
        PrivateKey::from_der(&key)?
    } else {
        PrivateKey::from_pem(&key)?
    };

    let cert_chain = if cert_path.map_or(true, |p| p.extension().map_or(false, |x| x == "der")) {
        CertificateChain::from_certs(once(Certificate::from_der(&cert)?))
    } else {
        CertificateChain::from_pem(&cert)?
    };

    Ok((key, cert_chain))
}

/// QUICCtest server CLI options
#[derive(Clap, Clone)]
#[clap(version = "0.1", author = "Dherse <seb@dherse.dev>")]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct CliOpt {
    /// A level of verbosity (not present = error only, -v = warnings, -vv = info, -vvv = debug, -vvvv = trace)
    #[clap(short, long, parse(from_occurrences))]
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
