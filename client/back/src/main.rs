use std::net::{TcpListener, TcpStream};
use ring::{agreement, rand, signature::{self, KeyPair}};
use ring::aead;
use ring::aead::BoundKey;
use ring::digest::SHA256_OUTPUT_LEN;
use ring::error::Unspecified;
use ring::hkdf::{HKDF_SHA256, Okm, Prk, Salt};
use ring::signature::Ed25519KeyPair;
use tungstenite::{accept, Message, WebSocket};
use std::env;
use rocket::http::Status;
use std::sync::{Mutex, Arc};

#[macro_use] extern crate rocket;


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
    signature
}

fn establish_listener() -> Result<TcpListener, std::io::Error> {
    let port = match env::var("LISTENER") {
        Ok(val) => val,
        Err(e) => panic!("Couldn't read LISTENER port env: {}", e),
    };

    match TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(listener) => Ok(listener),
        Err(e) => {
            eprint!("Failed to connect {}", e);
            return Err(e);
        }
    }
}

fn establishing_websocket() -> WebSocket<TcpStream> {
    let listener = match establish_listener() {
        Ok(k) => k,
        Err(E) => panic!("Error whilst establishing listener: {}", E)
    };

    println!("Waiting for incoming connection...");
    loop {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    match accept(stream) {
                        Ok(k) => {
                            eprintln!("Connected");
                            return k;
                        }
                        Err(_e) => {
                            continue;
                        }
                    };
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {:?}", e);
                    continue;
                }
            }
        }
    }

}

async fn handshake (socket: Arc<Mutex<WebSocket<TcpStream>>>, signing_keypair: &Ed25519KeyPair)
              -> ([u8; 32], ring::signature::UnparsedPublicKey<Vec<u8>>)
{
    let (dh_private, dh_public) = diffie_hellman();
    let public_key = signing_keypair.public_key().as_ref().to_vec();
    let signature = sign(&dh_public, signing_keypair);

    let mut socket = socket.lock().unwrap();

    let _ = socket.send(Message::Binary(dh_public));
    let _ = socket.send(Message::Binary(signature));
    let _ = socket.send(Message::Binary(public_key));

    let peer_dh_public = loop {
        match socket.read() {
            Ok(msg) => {
                match msg {
                    Message::Binary(bin) => { break bin },
                    _ => continue
                }
            }
            Err(e) => panic!("Error while reading dh_key: {}", e)
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
            Err(e) => panic!("Error while reading signature: {}", e)
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
            Err(e) => panic!("Error while reading signature: {}", e)
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
    let mut in_out = message.to_owned();
    let tag = sealing_key.seal_in_place_separate_tag(associated_data, &mut in_out).unwrap();
    println!("cyphering {:?}", in_out);
    return (tag, in_out)
}

fn send_message
(
    socket: Arc<Mutex<WebSocket<TcpStream>>>,
    message: &str,
    signing_keypair: &Ed25519KeyPair,
    sealing_key: &mut aead::SealingKey<CounterNonceSequence>
)
{
    println!("sending_message1");
    let (tag, encrypted_message) = encrypt(message.as_ref(), sealing_key);

    let tag_and_enc_message = [tag.as_ref(), &encrypted_message].concat();
    let locked_key = signing_keypair;

    let signature = sign(&tag_and_enc_message, &locked_key);
    let mut socket = socket.lock().unwrap();
    println!("sending a bin blob");
    let _ = socket.send(Message::Binary(encrypted_message));
    let _ = socket.send(Message::Binary(tag.as_ref().to_vec()));
    let _ = socket.send(Message::Binary(signature));
    println!("send_message2");

}

struct MySharedState {
    socket: Arc<Mutex<WebSocket<TcpStream>>>,
    signing_keypair: Ed25519KeyPair,
    sealing_key: Arc<Mutex<aead::SealingKey<CounterNonceSequence>>>,
}

#[post("/", format="text", data = "<input>")]
fn my_endpoint(state: &rocket::State<MySharedState>, input: String) -> Status {
    println!("my_endpoint Received a message on endpoint");
    let mut sealing_key = &mut *state.inner().sealing_key.lock().unwrap();
    let socket = state.inner().socket.clone();
    let signing_keypair = &state.inner().signing_keypair;
    println!("my_endpoint middle message");
    let message = &input;
    send_message(socket, message, signing_keypair, &mut sealing_key);
    println!("my_endpoint Send the message over websocket");
    Status::Ok
}

#[tokio::main]
async fn main() -> Result<(), rocket::Error> {
    let socket = Arc::new(
            std::sync::Mutex::new(
                establishing_websocket()
            )
        );

    let nonce_sequence = CounterNonceSequence(694201337);

    let signing_keypair = signing_keys_generator();
    let (symmetric_key, _) = handshake(socket.clone(), &signing_keypair).await;

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &symmetric_key).unwrap();
    let sealing_key = Arc::new(Mutex::new(aead::SealingKey::new(unbound_key, nonce_sequence)));

    let shared_state = MySharedState{
        socket: socket,
        signing_keypair: signing_keypair,
        sealing_key: sealing_key,
    };

    let portw = match env::var("REST") {
        Ok(val) => val,
        Err(e) => panic!("Couldn't read REST port env: {}", e),
    };
    let portw: u16 = portw.parse().expect("PORT must be a valid integer");

    println!("waiting for messages");

    let figment = rocket::Config::figment()
        .merge(("address", "0.0.0.0"))
        .merge(("port", portw));

    rocket::custom(figment)
        .manage(shared_state)
        .mount("/", routes![my_endpoint])
        .launch()
        .await?;

    println!("rocket launched");

    Ok(())
}
