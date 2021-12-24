use crate::AgentError;
use futures::StreamExt;

use libp2p::core::upgrade;
use libp2p::swarm::SwarmBuilder;
use libp2p::tcp::TokioTcpConfig;
use libp2p::{identity, mplex, noise, ping, PeerId, Transport};
use tokio;

pub struct VeronymousRouterAgentServer {}

impl VeronymousRouterAgentServer {
    pub async fn start(address: &String) -> Result<(), AgentError> {
        // TODO: Split method up

        // Generate a peer id
        let key_pair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(key_pair.public());

        info!("Server peer id: {}", peer_id.to_string());

        // Generate keys for encryption
        let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(&key_pair)
            .map_err(|e| AgentError::InitializationError(e.to_string()))?;

        // TODO: Verify and understand all of these parameters
        // TODO: Why isn't multiplex an option?
        let transport = TokioTcpConfig::new()
            .nodelay(true)
            .upgrade(upgrade::Version::V1) // Not sure if this is needed
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .boxed();

        // Start the server (swarm)

        // TODO: Replace with composed behaviour
        let behaviour = ping::Behaviour::new(ping::Config::new().with_keep_alive(true));

        let mut swarm = SwarmBuilder::new(transport, behaviour, peer_id)
            .executor(Box::new(|flut| {
                tokio::spawn(flut);
            }))
            .build();

        let address = address
            .parse()
            .map_err(|_| AgentError::ConfigError("Could not parse address".into()))?;

        swarm.listen_on(address).map_err(|e| {
            AgentError::InitializationError(format!("Could start server. {}", e.to_string()))
        })?;

        loop {
            match swarm.select_next_some().await {
                _ => {
                    info!("Got a swarm event")
                }
            }
        }
    }
}
