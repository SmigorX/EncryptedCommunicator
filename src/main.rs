use std::net::{TcpListener, TcpStream};
use ring::{agreement, rand, signature::{self, KeyPair}};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hkdf::{HKDF_SHA256, Okm, Prk, Salt};
use ring::signature::Ed25519KeyPair;
use tungstenite::{accept, connect, Message, WebSocket};
use tungstenite::stream::MaybeTlsStream;

fn signing_keys_generator() -> Ed25519KeyPair {
    let rng = rand::SystemRandom::new();
    let bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = signature::Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap();
    return keypair
}

fn diffie_hellman () -> (agreement::EphemeralPrivateKey, Vec<u8>) {
    let rng = rand::SystemRandom::new();
    let algo = &agreement::ECDH_P384;
    let private_key = agreement::EphemeralPrivateKey::generate(algo, &rng).unwrap();
    let public_key = private_key.compute_public_key().unwrap();
    let public_key = agreement::UnparsedPublicKey::new(algo, public_key.as_ref()).as_ref().to_vec();
    return (private_key, public_key)
}

fn sign (message: &Vec<u8>, keypair: &Ed25519KeyPair) -> Vec<u8> {
    let signature = keypair.sign(&message).as_ref().to_vec();
    signature
}
enum BindOrConnectResult {
    TcpListener(TcpListener),
    WebSocket(WebSocket<MaybeTlsStream<TcpStream>>),
}

fn bind_or_connect() -> Result<BindOrConnectResult, tungstenite::Error> {
    match TcpListener::bind("127.0.0.1:8080") {
        Ok(listener) => Ok(BindOrConnectResult::TcpListener(listener)),
        Err(_) => {
            match connect("ws://127.0.0.1:8080") {
                Ok((socket, _)) => Ok(BindOrConnectResult::WebSocket(socket)),
                Err(e) => {
                    eprint!("Failed to connect {}", e);
                    return Err(e);
                }
            }
        }
    }
}

enum EstablishingWebsocketResult {
    Plain(WebSocket<TcpStream>),
    Tls(WebSocket<MaybeTlsStream<TcpStream>>),
}

fn establishing_websocket() -> EstablishingWebsocketResult {
    match bind_or_connect() {
        Ok(result) => {
            match result {
                BindOrConnectResult::TcpListener(listener) => {
                    println!("Waiting for incoming connection...");
                    loop {
                        for stream in listener.incoming() {
                            match stream {
                                Ok(stream) => {
                                    let socket = accept(stream).expect("Error during WebSocket handshake");
                                    println!("WebSocket connected successfully");
                                    return EstablishingWebsocketResult::Plain(socket);
                                }
                                Err(e) => {
                                    eprintln!("Error accepting connection: {:?}", e)
                                }
                            }
                        }
                    }
                }
                BindOrConnectResult::WebSocket(socket) => {
                    println!("WebSocket connected successfully");
                    return EstablishingWebsocketResult::Tls(socket);
                }
            }
        }
        Err(e) => {
            panic!("Couldn't establish a listener: {}", e)
        }
    }
}

enum UnifiedWebSocket {
    Plain(WebSocket<TcpStream>),
    Tls(WebSocket<MaybeTlsStream<TcpStream>>),
}

impl UnifiedWebSocket {
    fn send(&mut self, message: Message) -> Result<(), tungstenite::Error> {
        match self {
            UnifiedWebSocket::Plain(socket) => socket.send(message),
            UnifiedWebSocket::Tls(socket) => socket.send(message),
        }
    }

    fn read(&mut self) -> Result<Message, tungstenite::Error> {
        match self {
            UnifiedWebSocket::Plain(socket) => socket.read(),
            UnifiedWebSocket::Tls(socket) => socket.read(),
        }
    }
}



fn handshake (socket: &mut UnifiedWebSocket, signing_keypair: &Ed25519KeyPair)
-> ([u8; 32], ring::signature::UnparsedPublicKey<Vec<u8>>)
{
    let (dh_private, dh_public) = diffie_hellman();
    let public_key = signing_keypair.public_key().as_ref().to_vec();
    let signature = sign(&dh_public, signing_keypair);

    socket.send(Message::Binary(dh_public));
    socket.send(Message::Binary(signature));
    socket.send(Message::Binary(public_key));

    let peer_dh_public = loop {
            match socket.read() {
                Ok(msg) => {
                    match msg {
                        Message::Binary(bin) => { break bin },
                        _ => continue
                    }
                }
                Err(e) => panic!("Error while reading handshake: {}", e)
            };
        };
    let peer_signature = loop {
        match socket.read() {
            Ok(msg) => {
                match msg {
                    Message::Binary(bin) => { break bin },
                    _ => continue
                }
            }
            Err(e) => panic!("Error while reading handshake: {}", e)
        };
    };
    let peer_verification = loop {
        match socket.read() {
            Ok(msg) => {
                match msg {
                    Message::Binary(bin) => { break bin },
                    _ => continue
                }
            }
            Err(e) => panic!("Error while reading handshake: {}", e)
        };
    };

    let peer_verification = signature::UnparsedPublicKey::new(&signature::ED25519, peer_verification);
    match peer_verification.verify(&peer_dh_public, &peer_signature) {
        Err(e) => panic!("Peer signature verification negative: {}", e),
        _ => (),
    };

    let peer_dh_public = agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, peer_dh_public);

    let symmetric_key = match agreement::agree_ephemeral
        (dh_private, &peer_dh_public, |key| {derive_new_key(key)})
    {
        Err(e) => panic!("Couldn't derive a common symmetric key: {}", e),
        Ok(k) => k,
    };
    println!("Łała łiłu, that's a very nice: {:?}", symmetric_key);

    return (symmetric_key, peer_verification);
}


fn derive_new_key(current_key: &[u8]) -> [u8; 32] {
    let salt = Salt::new(HKDF_SHA256, b"salt & sugar");
    let context_data = &["Next iteration of symmetric key from kdf".as_bytes()];
    let pseudo_rand_key: Prk = salt.extract(current_key);
    let output_key_material: Okm<ring::hkdf::Algorithm> = pseudo_rand_key.expand(context_data, HKDF_SHA256).unwrap();
    let mut result = [0u8; SHA256_OUTPUT_LEN];
    output_key_material.fill(&mut result).unwrap();
    return result;

}

fn main() {
    let mut socket: UnifiedWebSocket = match establishing_websocket() {
        EstablishingWebsocketResult::Plain(socket) => {
            UnifiedWebSocket::Plain(socket)
        }
        EstablishingWebsocketResult::Tls(socket) => {
            UnifiedWebSocket::Tls(socket)
        }
    };

    let signing_keypair = signing_keys_generator();
    let (current_symmetric_key, peer_verification) = handshake(&mut socket, &signing_keypair);
}
