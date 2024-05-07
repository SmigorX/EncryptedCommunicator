use std::io::Write;
use std::net::TcpStream;
use ring::{agreement, rand, signature::{self, KeyPair}};
use ring::aead;
use ring::aead::BoundKey;
use ring::digest::SHA256_OUTPUT_LEN;
use ring::error::Unspecified;
use ring::hkdf::{HKDF_SHA256, Okm, Prk, Salt};
use ring::signature::Ed25519KeyPair;
use tungstenite::{connect, Message, WebSocket};
use tungstenite::stream::MaybeTlsStream;
use std::{env, sync::{Arc, Mutex}};
use std::fs::File;
use std::io;
use std::process::exit;


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

fn establishing_websocket() -> WebSocket<MaybeTlsStream<TcpStream>> {
    let port = match env::var("LISTENER") {
        Ok(val) => val,
        Err(e) => panic!("Couldn't read LISTENER port env: {}", e),
    };
    let (websocket, _) =
        loop {
            match connect(format!("ws://client-backend:{}", port)) {
                Ok(result) => {
                    println!("connected");
                    break result;
                },
                Err(_) => continue
            };
        };
    return websocket
}

fn handshake (socket: &mut WebSocket<MaybeTlsStream<TcpStream>>, signing_keypair: &Ed25519KeyPair)
              -> ([u8; 32], ring::signature::UnparsedPublicKey<Vec<u8>>)
{
    let (dh_private, dh_public) = diffie_hellman();
    let public_key = signing_keypair.public_key().as_ref().to_vec();
    let signature = sign(&dh_public, signing_keypair);

    match socket.send(Message::Binary(dh_public)) {
        Err(e) => eprintln!("Error whilst sending dh handshake Binary1 {}", e),
        _ => ()
    };
    match socket.send(Message::Binary(signature)) {
        Err(e) => eprintln!("Error whilst sending dh handshake Binary2 {}", e),
        _ => ()
    };
    match socket.send(Message::Binary(public_key)) {
        Err(e) => eprintln!("Error whilst sending dh handshake Binary3 {}", e),
        _ => ()
    };

    let peer_dh_public = loop {
        match socket.read() {
            Ok(msg) => {
                match msg {
                    Message::Binary(bin) => { break bin },
                    _ => continue
                }
            }
            Err(e) => panic!("Error while reading handshake1: {}", e)
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
            Err(e) => panic!("Error while reading handshake2: {}", e)
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
            Err(e) => panic!("Error while reading handshake3: {}", e)
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

fn decrypt
(
    tag: aead::Tag,
    encrypted_message: &[u8],
    opening_key: &mut aead::OpeningKey<CounterNonceSequence>
)
    -> Vec<u8>
{
    let associated_data = aead::Aad::empty();
    let mut cypher_text_with_tag = [encrypted_message, tag.as_ref()].concat();
    let decrypted_data = opening_key.open_in_place( associated_data, &mut cypher_text_with_tag).unwrap().to_owned();
    println!("Decyphered {}", String::from_utf8(decrypted_data.to_vec()).unwrap());
    return decrypted_data;
}

fn file_check() -> Result<File, io::Error> {
    let file = match File::open("messages.txt") {
        Ok(file) => {
            println!("File opened successfully.");
            file
        }
        Err(ref error) if error.kind() == io::ErrorKind::NotFound => {
            match File::create("messages.txt") {
                Ok(file) => {
                    println!("File created.");
                    file
                }
                Err(err) => return Err(err),
            }
        }
        Err(error) => return Err(error),
    };
    Ok(file)
}

fn write_message_to_file(message: Vec<u8>, file: &mut File) {
    file.write_all(&message).unwrap();
    file.write_all(b"\n").unwrap();
}

fn receive_message
(
    encrypted_message: &[u8],
    tag_bytes: &[u8],
    signature: &[u8],
    verifying_key: &ring::signature::UnparsedPublicKey<Vec<u8>>,
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

#[tokio::main]
async fn main() -> Result<(), rocket::Error> {
    let mut socket: WebSocket<MaybeTlsStream<TcpStream>> = establishing_websocket();

    let nonce_sequence = CounterNonceSequence(694201337);

    let signing_keypair = Arc::new(Mutex::new(signing_keys_generator()));
    let (symmetric_key, peer_signature_verification_key) = handshake(&mut socket, &signing_keypair.lock().unwrap());

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &symmetric_key).unwrap();
    let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_sequence);

    let mut file = match file_check() {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Error opening or creating file: {}", error);
            exit(4)
        }
    };

    loop {
        let (encrypted_message, tag, signature): (Vec<u8>, Vec<u8>, Vec<u8>) = match socket.read() {
            Ok(Message::Binary(payload)) => {
                let encrypted_message = payload;
                let tag = match socket.read() {
                    Ok(Message::Binary(tag)) => tag,
                    _ => continue,
                };
                let signature = match socket.read() {
                    Ok(Message::Binary(signature)) => signature,
                    _ => continue,
                };
                (encrypted_message, tag, signature)
            }
            _ => continue,
        };
        let message = receive_message(&encrypted_message, &tag,
                                      &signature, &peer_signature_verification_key,
                                      &mut opening_key);
        write_message_to_file(message, &mut file)
    }
}
