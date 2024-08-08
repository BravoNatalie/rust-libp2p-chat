
# Rust libp2p Chat

A peer-to-peer decentralized chat app built with Rust and libp2p. It utilizes the gossipsub protocol for message propagation, combined with mDNS for peer discovery, and the identify protocol for exchanging peer information, such as public keys and network addresses. This app demonstrates how peers can connect, discover each other via mDNS, and engage in real-time chat sessions.

## Usage

1. Open at least two terminal windows and start an instance in each by typing:
   ```sh
   cargo run
   ```

2. Mutual mDNS discovery may take a few seconds. Once peers discover each other, you'll see a message like:
   ```sh
   mDNS discovered a new peer: {peerId}
   Sent identify info to PeerId(peerId)
   ```

3. Type a message and press Enter. The message will be sent and displayed in the other terminal.

4. Close the app with `Ctrl-C`. You can add more peers by opening additional terminal windows and running the same command.

When a new peer is found using mDNS, it can join the chat, and all other peers will receive its messages. If a participant leaves the app, the remaining peers will recognize the departure through an mDNS expiration event and update their list by removing the peer.