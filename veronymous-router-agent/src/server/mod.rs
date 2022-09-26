use crate::service::router::VeronymousRouterAgentService;
use crate::{AgentError, VeronymousAgentConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use veronymous_connection::model::{ConnectMessage, SerializableMessage, CONNECT_REQUEST_SIZE};

// TODO: Review shared state - https://tokio.rs/tokio/tutorial/shared-state

// NOTE: ATM there is only one request
const REQUEST_SIZE: usize = CONNECT_REQUEST_SIZE + 1;

// https://tokio.rs/tokio/tutorial/shared-state
type RouterService = Arc<Mutex<VeronymousRouterAgentService>>;

pub struct VeronymousRouterAgentServer {
    address: String,

    tls_acceptor: TlsAcceptor,

    service: RouterService,

    epoch_length: u64,
}

impl VeronymousRouterAgentServer {
    pub async fn create() -> Result<Self, AgentError> {
        let config = VeronymousAgentConfig::load().unwrap();

        Ok(Self {
            address: config.address.clone(),
            tls_acceptor: create_tls_acceptor(&config)?,
            service: Arc::new(Mutex::new(
                VeronymousRouterAgentService::create(&config).await?,
            )),
            epoch_length: config.epoch_length * 60,
        })
    }

    pub async fn start(&mut self) -> Result<(), AgentError> {
        info!("Starting server on {}...", self.address);
        let listener = TcpListener::bind(&self.address)
            .await
            .map_err(|e| AgentError::InitializationError(e.to_string()))?;

        self.schedule_connection_cleaner().await;

        self.listen(&listener).await?;

        Ok(())
    }

    async fn listen(&mut self, listener: &TcpListener) -> Result<(), AgentError> {
        loop {
            // Wait for tcp connection
            let (socket, address) = match listener.accept().await {
                Ok(connection) => connection,
                Err(err) => {
                    info!("Could not accept connection. {}", err.to_string());
                    continue;
                }
            };

            // Wait for tls connection
            let tls_acceptor = self.tls_acceptor.clone();
            let mut socket = match tls_acceptor.accept(socket).await {
                Ok(socket) => socket,
                Err(err) => {
                    debug!("Could not accept TLS connection. {:?}", err);
                    continue;
                }
            };

            debug!("Accepted connection from {:?}", address);

            let service = self.service.clone();

            tokio::spawn(async move {
                match Self::handle_connection(service, &mut socket).await {
                    Err(err) => {
                        info!("{:?}", err);
                        Self::close_connection(&mut socket).await;
                    }
                    _ => {}
                };
            });
        }
    }

    async fn close_connection(socket: &mut TlsStream<TcpStream>) {
        match socket.write_u8(0).await {
            Ok(_) => {}
            Err(e) => {
                error!("Could not write error code. {:?}", e);
            }
        };
        match socket.flush().await {
            Ok(_) => {}
            Err(e) => {
                error!("Could not flush connection. {:?}", e);
            }
        };
    }

    /*
    * Removes all connections after each epoch

    */
    async fn schedule_connection_cleaner(&self) {
        info!("Scheduling connection cleaner...");

        //let next_epoch = self.epoch_service.next_epoch();
        let next_epoch = self.next_epoch();
        let epoch_duration = Duration::from_secs(self.epoch_length);

        info!("Next epoch: {:?}", next_epoch);
        info!("Epoch duration: {}s", epoch_duration.as_secs());

        let service = self.service.clone();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval_at(next_epoch, epoch_duration);
            loop {
                interval_timer.tick().await;
                info!("Clearing connections...");

                let mut locked_service = service.lock().await;

                match locked_service.clear_connections().await {
                    Ok(_) => info!("Connections cleared!"),
                    Err(err) => error!("Got error while clearing connections. {:?}", err),
                }
            }
        });
    }

    async fn handle_connection(
        service: RouterService,
        socket: &mut TlsStream<TcpStream>,
    ) -> Result<(), AgentError> {
        // Read the request
        let (request_size, request_bytes) = Self::read_request(socket).await?;

        // Handle the request
        Self::handle_request(service, request_size, &request_bytes, socket).await?;

        Ok(())
    }

    async fn handle_request<'a>(
        service: RouterService,
        request_size: usize,
        request_bytes: &[u8; REQUEST_SIZE],
        socket: &mut TlsStream<TcpStream>,
    ) -> Result<(), AgentError> {
        // Initial validation
        if request_size != REQUEST_SIZE {
            return Err(AgentError::BadRequest(format!(
                "Bad connect request size. Expected {}, but got {}",
                REQUEST_SIZE, request_size
            )));
        }

        // Decode connect message
        let message = ConnectMessage::from_bytes(request_bytes)
            .map_err(|err| AgentError::BadRequest(format!("{:?}", err)))?;

        let mut service = service.lock().await;

        // Process the message
        match message {
            ConnectMessage::ConnectRequest(request) => {
                service.handle_connect_request(&request, socket).await?;
            }
            _ => {
                return Err(AgentError::BadRequest(format!(
                    "Unsupported message: {:?}",
                    message
                )));
            }
        }

        Ok(())
    }

    // Only one request (ConnectRequest) exists for now
    async fn read_request(
        socket: &mut TlsStream<TcpStream>,
    ) -> Result<(usize, [u8; REQUEST_SIZE]), AgentError> {
        let mut buffer = [0; REQUEST_SIZE];

        // Number of bytes read
        let n = socket.read(&mut buffer).await.map_err(|e| {
            AgentError::IoError(format!("Could not read request. {}", e.to_string()))
        })?;

        Ok((n, buffer))
    }

    pub fn next_epoch(&self) -> Instant {
        let now = SystemTime::now();
        let now_instant = Instant::now();

        let now = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Get the current epoch start
        let current_epoch = now - (now % self.epoch_length);
        let next_epoch = current_epoch + self.epoch_length;

        let time_until_next_epoch = next_epoch - now;

        now_instant + Duration::from_secs(time_until_next_epoch)
    }
}

fn create_tls_acceptor(config: &VeronymousAgentConfig) -> Result<TlsAcceptor, AgentError> {
    // Load the tls config
    let tls_config = create_tls_server_config(config)?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

fn create_tls_server_config(config: &VeronymousAgentConfig) -> Result<ServerConfig, AgentError> {
    // Load certs
    let certs = load_certs(&config.tls_cert)?;

    // Load the cert key
    let private_key = load_cert_key(&config.tls_cert_key)?;

    // Assemble the config
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| {
            AgentError::ConfigError(format!("Could not create server tls config. {:?}", e))
        })?;

    Ok(server_config)
}

fn load_certs(certs_path: &String) -> Result<Vec<Certificate>, AgentError> {
    let file = File::open(certs_path)
        .map_err(|e| AgentError::ConfigError(format!("Could not load cert file. {:?}", e)))?;

    let raw_certs = certs(&mut BufReader::new(file))
        .map_err(|e| AgentError::ConfigError(format!("Could not load certs. {:?}", e)))?;

    let mut certs = Vec::with_capacity(raw_certs.len());

    for cert in raw_certs {
        certs.push(Certificate(cert));
    }

    Ok(certs)
}

fn load_cert_key(key_path: &String) -> Result<PrivateKey, AgentError> {
    let file = File::open(key_path)
        .map_err(|e| AgentError::ConfigError(format!("Could not load key file. {:?}", e)))?;

    let mut raw_keys = rsa_private_keys(&mut BufReader::new(file))
        .map_err(|e| AgentError::ConfigError(format!("Could not load private key. {:?}", e)))?;

    let private_key = PrivateKey(raw_keys.remove(0));

    Ok(private_key)
}
