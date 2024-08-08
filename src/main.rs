use clap::Parser;
use futures::StreamExt;
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use tokio::{fs, io, io::AsyncBufReadExt, select};
use std::{
    collections::hash_map::DefaultHasher, error::Error, hash::{Hash, Hasher}, iter, net::{IpAddr, Ipv4Addr}, path::Path, time::Duration
};
use libp2p::{
    gossipsub, identify, identity::{self, Keypair}, mdns, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux,  multiaddr::{Multiaddr, Protocol}, PeerId, Swarm, SwarmBuilder
};

const PORT_TPC: u16 = 0;
const PORT_QUIC: u16 = 0; //9091;
const LOCAL_KEY_PATH: &str = "./local_key";
const GOSSIPSUB_CHAT_TOPIC: &str = "local-net";
const LISTEN_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // TODO: parse cli options using clap

    let local_key = read_or_create_identity(Path::new(LOCAL_KEY_PATH))
        .await
        .context("Failed to read identity")?;


    let mut swarm = create_swarm(local_key)?;

     // Create a Gossipsub topic
    let chat_topic = gossipsub::IdentTopic::new(GOSSIPSUB_CHAT_TOPIC);
    // Subscribe to the Gossipsub topic
    swarm.behaviour_mut().gossipsub.subscribe(&chat_topic)?;

   
    let address_quic = Multiaddr::from(LISTEN_ADDRESS)
    .with(Protocol::Udp(PORT_QUIC))
    .with(Protocol::QuicV1);

    let address_tcp = Multiaddr::from(LISTEN_ADDRESS)
    .with(Protocol::Tcp(PORT_TPC));

    // tell the swarm to Listen on all interfaces and whatever port the OS assigns
    // swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on(address_tcp).expect("listen on tcp");
    // swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on(address_quic).expect("listen on quic");

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    println!("Enter messages via STDIN and they will be sent to connected peers using Gossipsub");

    // Dial the peer identified by the multi-address given as the second
    // command-line argument, if any.
    if let Some(addr) = std::env::args().nth(1) {
        let remote: Multiaddr = addr.parse()?;
        swarm.dial(remote)?;
        println!("Dialed {addr}")
    }

    // Kick it off
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                    .publish(chat_topic.clone(), line.as_bytes()) {
                    println!("Publish error: {e:?}");
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => println!(
                        "Got message: '{}' with id: {id} from peer: {peer_id}",
                        String::from_utf8_lossy(&message.data),
                    ),
                 // Prints peer id identify info is being sent to.
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Sent { peer_id, .. })) => {
                    println!("Sent identify info to {peer_id:?}")
                }
                // Prints out the info received via the identify event
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                    println!("Received {info:?}")
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
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

async fn read_or_create_identity(path: &Path) -> Result<identity::Keypair> {
    if path.exists() {
        let bytes = fs::read(&path).await?;

        info!("Using existing identity from {}", path.display());

        return Ok(identity::Keypair::from_protobuf_encoding(&bytes)?); // This only works for ed25519 but that is what we are using.
    }

    let identity = identity::Keypair::generate_ed25519();

    fs::write(&path, &identity.to_protobuf_encoding()?).await?;

    info!("Generated new identity and wrote it to {}", path.display());

    Ok(identity)
}