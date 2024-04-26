use std::convert::Infallible;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use ring::{agreement, rand, signature::{self, KeyPair}};
use ring::aead;
use ring::aead::BoundKey;
use ring::digest::SHA256_OUTPUT_LEN;
use ring::error::Unspecified;
use ring::hkdf::{HKDF_SHA256, Okm, Prk, Salt};
use ring::signature::Ed25519KeyPair;
use tungstenite::{accept, connect, Message, WebSocket};
use tungstenite::stream::MaybeTlsStream;
use axum::{routing, Router};
use std::env;
use http;
use http::{Response, StatusCode};


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

fn sign (message: &[u8], keypair: &Ed25519KeyPair) -> Vec<u8> {
    let signature = keypair.sign(&message).as_ref().to_vec();
    println!("{:?}", signature);
    signature
}
enum BindOrConnectResult {
    TcpListener(TcpListener),
    WebSocket(WebSocket<MaybeTlsStream<TcpStream>>),
}

fn bind_or_connect() -> Result<BindOrConnectResult, tungstenite::Error> {
    let port = match env::var("LISTENER") {
        Ok(val) =>(val),
        Err(e) => panic!("Couldn't read LISTENER port env: {}", e),
    };
    match TcpListener::bind(format!("127.0.0.1:{}", port)) {
        Ok(listener) => Ok(BindOrConnectResult::TcpListener(listener)),
        Err(_) => {
            match connect(format!("ws://127.0.0.1:{}", port)) {
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
struct CounterNonceSequence (u32);

impl aead::NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; aead::NONCE_LEN];
        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);
        self.0 += 1;
        return aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

fn encrypt (message: &[u8], sealing_key: &mut aead::SealingKey<CounterNonceSequence>)
    -> (aead::Tag, Vec<u8>)
{
    let associated_data = aead::Aad::empty();
    let mut in_out = message.clone().to_owned();
    let tag = sealing_key.seal_in_place_separate_tag(associated_data, &mut in_out).unwrap();
    println!("cyphering {:?}", in_out);
    return (tag, in_out)
}

fn decrypt
(
    tag: aead::Tag,
    encrypted_message: &[u8],
    opening_key: &mut aead::OpeningKey<CounterNonceSequence>
)
    -> Vec<u8>
{
    let associated_data = aead::Aad::empty();
    //let in_out = encrypted_message;
    let mut cypher_text_with_tag = [encrypted_message, tag.as_ref()].concat();
    let decrypted_data = opening_key.open_in_place( associated_data, &mut cypher_text_with_tag).unwrap().to_owned();
    println!("Decyphered {}", String::from_utf8(decrypted_data.to_vec()).unwrap());
    return decrypted_data;
}

fn send_message
(
    socket: &mut UnifiedWebSocket,
    message: &str,
    signing_keypair: &Ed25519KeyPair,
    sealing_key: &mut aead::SealingKey<CounterNonceSequence>
)
{
    let (tag, encrypted_message) = encrypt(message.as_ref(), sealing_key);

    let tag_and_enc_message = [tag.as_ref(), &encrypted_message].concat();
    let signature = sign(&tag_and_enc_message, &signing_keypair);

    socket.send(Message::Binary(encrypted_message));
    socket.send(Message::Binary(tag.as_ref().to_vec()));
    socket.send(Message::Binary(signature));
}

fn receive_message
(
    encrypted_message: &[u8],
    tag_bytes: &[u8],
    signature: &[u8],
    verifying_key: ring::signature::UnparsedPublicKey<Vec<u8>>,
    opening_key: &mut aead::OpeningKey<CounterNonceSequence>,
)
    -> Vec<u8>
{
    let tag= ring::aead::Tag::try_from(tag_bytes).unwrap();

    let tag_and_enc_message = [tag.as_ref(), encrypted_message].concat();
    match verifying_key.verify(&tag_and_enc_message, signature) {
        Ok(_) => (),
        Err(e) => {panic!("Couldn't verify an incoming message {}", e)}
    }
    let message = decrypt(tag, encrypted_message, opening_key);
    return message;
}

fn request_handler
(
    socket: &mut UnifiedWebSocket,
    message: String,
    signing_keypair: &Ed25519KeyPair,
    sealing_key: &mut aead::SealingKey<CounterNonceSequence>
)
    -> Response<(StatusCode)>
{
    send_message(socket, &message, signing_keypair, sealing_key);
    Response::new(http::StatusCode::OK)
}

fn hello_world() -> Response<(String)> {
    let builder = http::Response::builder().status(http::StatusCode::ACCEPTED);
    builder.body("wawawiwiu".to_owned()).unwrap()
}


#[tokio::main]
async fn main() {
    let mut socket: UnifiedWebSocket = match establishing_websocket() {
        EstablishingWebsocketResult::Plain(socket) => {
            UnifiedWebSocket::Plain(socket)
        }
        EstablishingWebsocketResult::Tls(socket) => {
            UnifiedWebSocket::Tls(socket)
        }
    };

    let nonce_sequence_rx = CounterNonceSequence(694201337);
    let nonce_sequence_tx = CounterNonceSequence(694201337);

    let signing_keypair = signing_keys_generator();
    let (symmetric_key, peer_signature_verification_key) = handshake(&mut socket, &signing_keypair);

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &symmetric_key).unwrap();
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence_tx);
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &symmetric_key).unwrap();
    let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_sequence_rx);

    let port = match env::var("REST") {
        Ok(val) =>(val),
        Err(e) => panic!("Couldn't read REST port env: {}", e),
    };

    let app = Router::new()
        .route("/",
               routing::get(|a| {request_handler(&mut socket, a, &signing_keypair, &mut sealing_key)}));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
