use clap::{Parser, ValueEnum};
use futures::StreamExt;
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use tokio::{fs, io, io::AsyncBufReadExt, select};
use std::{
    collections::hash_map::DefaultHasher, error::Error, hash::{Hash, Hasher}, net::IpAddr, path::Path, time::Duration
};
use libp2p::{
    gossipsub, identify, identity, mdns, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux,  multiaddr::{Multiaddr, Protocol}, PeerId, Swarm, SwarmBuilder
};

// - Port 0 uses a port assigned by the OS.
const PORT_TPC: u16 = 0;
const PORT_QUIC: u16 = 0; //9091;
const LOCAL_KEY_PATH: &str = "./local_key";
const GOSSIPSUB_CHAT_TOPIC: &str = "chat";

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

#[derive(Parser, Debug)]
#[clap(name = "decentralized chat peer")]
struct Args {
    /// Address to listen on.
    #[clap(long, default_value = "0.0.0.0")]
    listen_address: IpAddr,

    /// From where to get the identity keypair
    #[clap(value_enum, default_value_t = KeypairOpt::GENERATE )]
    keypair: KeypairOpt,

    /// Nodes to connect to on startup.
    #[clap(long)]
    connect: Option<Vec<Multiaddr>>,
}

/// Keypair options
#[derive(ValueEnum, Debug, Clone)]
enum KeypairOpt {
    /// Generate and save the keypair into ./local_key file
    GENERATE,
    
    /// Read keypair from ./local_key file
    FILE,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let local_key = read_or_create_identity(args.keypair)
        .await
        .context("Failed to get identity")?;


    let mut swarm = create_swarm(local_key)?;

    // Create a Gossipsub topic
    let chat_topic = gossipsub::IdentTopic::new(GOSSIPSUB_CHAT_TOPIC);
    // Subscribe to the Gossipsub topic
    swarm.behaviour_mut().gossipsub.subscribe(&chat_topic)?;

    let address_quic = Multiaddr::from(args.listen_address)
    .with(Protocol::Udp(PORT_QUIC))
    .with(Protocol::QuicV1);

    let address_tcp = Multiaddr::from(args.listen_address)
    .with(Protocol::Tcp(PORT_TPC));

    // tell the swarm to Listen on all interfaces and whatever port the OS assigns
    //"/ip4/0.0.0.0/udp/0/quic-v1"
    swarm.listen_on(address_tcp.clone()).expect("listen on tcp");
    //"/ip4/0.0.0.0/tcp/0"
    swarm.listen_on(address_quic.clone()).expect("listen on quic");

    // Dial the peers identified by the multi-address given as argument
    if let Some(addrs) = args.connect {
        for addr in addrs {
            info!("Dialing {addr}...");
            if let Err(e) = swarm.dial(addr.clone()) {
                error!("Failed to dial {addr}: {e}");
            }
        }
    }

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();
 
    // Kick it off
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                    .publish(chat_topic.clone(), line.as_bytes()) {
                    error!("Publish error: {e:?}");
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Local node is listening on {address}");
                },
                // Prints peer id identify info is being sent to.
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Sent { peer_id, .. })) => {
                    info!("Sent identify info to {peer_id:?}")
                }
                // Prints out the info received via the identify event
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                    info!("Received {info:?}")
                },
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        info!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        info!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => info!(
                        "Got message: '{}' with id: {id} from peer: {peer_id}",
                        String::from_utf8_lossy(&message.data),
                    ),
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                    debug!("{peer_id} subscribed to {topic}");
                }
                _ => {}
            }
        }
    }
}

fn create_swarm(local_key: identity::Keypair) -> Result<Swarm<Behaviour>> {
    let local_peer_id = PeerId::from(local_key.public());
    debug!("Local peer id: {local_peer_id}");

    // ----------------------------------------
    // # Define our protocols layer 
    // ----------------------------------------

    //** GOSSIPSUB  **//
    // Publish-subscribe message protocol.

    // To content-address message, we can take the hash of message and use it as an ID.
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    // Set a custom gossipsub configuration
    let gossipsub_config = gossipsub::ConfigBuilder::default()
     .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
     .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
     .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
     .build()
     .expect("Valid gossipsub configuration");

    // build a gossipsub network behaviour
    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    ).expect("Correct gossipsub behaviour configuration");

   
    //** IDENTIFY  **//
    // Exchanges identify info with other peers.

    let identify = identify::Behaviour::new(
        identify::Config::new(
            "/ipfs/0.1.0".into(), 
            local_key.public()
        )
    );


    //** MDNS  **//
    // Is used for peer discovery, allowing peers to find each other on the same local network without any configuration.

    let mdns = mdns::tokio::Behaviour::new(
        mdns::Config::default(), 
        local_key.public().to_peer_id()
    ).expect("Correct mdns behaviour configuration");

    // final network behaviour
    let behaviour =  Behaviour {
        gossipsub,
        identify,
        mdns
    };

    // ----------------------------------------
    // # create a Swarm with: identity, transport layer and network behaviour
    // ----------------------------------------

    Ok(
        SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp( // setup the Transport (it defines how to send bytes on the network)
            tcp::Config::default(), 
            noise::Config::new, // noise is a encryption scheme, it encrypts the data between nodes and provides forward secrecy
            yamux::Config::default // yamux is a multiplexer, it enables multiple parallel streams on a single TCP connection
        )?
        .with_quic()
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60))) 
        .build() // Build the Swarm to relay commands from NetworkBehaviour to Transport and events from Transport to NetworkBehaviour.
    )
}

async fn generate_and_save_identity(path: &Path ) -> Result<identity::Keypair> {
   
    let identity = identity::Keypair::generate_ed25519();

    fs::write(&path, &identity.to_protobuf_encoding()?).await?;

    info!("Generated new identity and wrote it to {}", path.display());

    Ok(identity)
}

async fn read_or_create_identity(keypair: KeypairOpt) -> Result<identity::Keypair> {
    let path: &Path = Path::new(LOCAL_KEY_PATH);

    match  keypair {
        KeypairOpt::GENERATE =>  generate_and_save_identity(path).await,
        KeypairOpt::FILE => {
            if path.exists() {
                let bytes = fs::read(&path).await?;
        
                info!("Using existing identity from {}", path.display());
        
                return Ok(identity::Keypair::from_protobuf_encoding(&bytes)?); // This only works for ed25519 but that is what we are using.
            }
            generate_and_save_identity(path).await
        }
    }
}