use crate::service::epoch::EpochService;
use crate::service::router::VeronymousRouterAgentService;
use crate::{AgentError, VeronymousAgentConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::Instant;
use veronymous_connection::model::{ConnectMessage, SerializableMessage, CONNECT_REQUEST_SIZE};

// TODO: Review shared state - https://tokio.rs/tokio/tutorial/shared-state

// NOTE: ATM there is only one request
const REQUEST_SIZE: usize = CONNECT_REQUEST_SIZE + 1;

// https://tokio.rs/tokio/tutorial/shared-state
type RouterService = Arc<Mutex<VeronymousRouterAgentService>>;

pub struct VeronymousRouterAgentServer {
    address: String,

    service: RouterService,

    epoch_service: EpochService,
}

impl VeronymousRouterAgentServer {
    pub async fn create() -> Result<Self, AgentError> {
        let config = VeronymousAgentConfig::load().unwrap();

        Ok(Self {
            address: config.address.clone(),
            service: Arc::new(Mutex::new(
                VeronymousRouterAgentService::create(&config).await?,
            )),
            epoch_service: EpochService::create(&config),
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
            let (mut socket, address) = match listener.accept().await {
                Ok(connection) => connection,
                Err(err) => {
                    info!("Could not accept connection. {}", err.to_string());
                    continue;
                }
            };

            debug!("Connected to {:?}", address);

            let service = self.service.clone();

            tokio::spawn(async move {
                match Self::handle_connection(service, &mut socket).await {
                    Err(err) => {
                        info!("{:?}", err);
                    }
                    _ => {}
                };
            });
        }
    }

    /*
     * Removes all connections after each epoch
     * TODO: Figure out a way to make this seamless (buffer)
     * TODO: Might want to put this in one of the services.
     * TODO: Add epoch sync?
     */
    async fn schedule_connection_cleaner(&self) {
        info!("Scheduling connection cleaner...");

        let next_epoch = self.epoch_service.next_epoch();
        let epoch_duration = self.epoch_service.epoch_duration();

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
        socket: &mut TcpStream,
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
        socket: &mut TcpStream,
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
        socket: &mut TcpStream,
    ) -> Result<(usize, [u8; REQUEST_SIZE]), AgentError> {
        let mut buffer = [0; REQUEST_SIZE];

        // Number of bytes read
        let n = socket.read(&mut buffer).await.map_err(|e| {
            AgentError::IoError(format!("Could not read request. {}", e.to_string()))
        })?;

        Ok((n, buffer))
    }
}
