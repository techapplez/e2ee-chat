use tokio_tungstenite::connect_async;
use futures_util::{SinkExt, StreamExt};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or Aes128Gcm
use aes_gcm::aead::{Aead, NewAead};
use rand::RngCore;
use base64::{encode, decode};
use std::io::{self, Write};
use serde::{Serialize, Deserialize};

const SHARED_SECRET: &[u8; 32] = b"iamaratfanandilikerustandidkwhat";

#[derive(Serialize, Deserialize)]
struct EncryptedMessage {
    nonce: String,
    ciphertext: String,
}

#[tokio::main]
async fn main() {
    let url = "ws://9b25-2a01-71a0-8405-d800-31c4-6ad1-a850-9b97.ngrok-free.app";
    let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
    let (mut write, mut read) = ws_stream.split();

    tokio::spawn(async move {
        while let Some(Ok(msg)) = read.next().await {
            if msg.is_binary() {
                let data = msg.into_data();
                if let Some(text) = decrypt_message(&data) {
                    println!("\n[Received] {}", text);
                    print!("> ");
                    io::stdout().flush().unwrap();
                }
            }
        }
    });

    loop {
        print!("> ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        if input.is_empty() { continue; }

        let encrypted = encrypt_message(input).expect("Encryption failed");
        write.send(tungstenite::Message::Binary(encrypted)).await.unwrap();
    }
}

fn encrypt_message(plaintext: &str) -> Option<Vec<u8>> {
    let key = Key::from_slice(SHARED_SECRET);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).ok()?;

    let msg = EncryptedMessage {
        nonce: encode(&nonce_bytes),
        ciphertext: encode(&ciphertext),
    };

    let json = serde_json::to_vec(&msg).ok()?;
    Some(json)
}

fn decrypt_message(data: &[u8]) -> Option<String> {
    let msg: EncryptedMessage = serde_json::from_slice(data).ok()?;
    let nonce_bytes = decode(&msg.nonce).ok()?;
    let ciphertext = decode(&msg.ciphertext).ok()?;

    let key = Key::from_slice(SHARED_SECRET);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
    String::from_utf8(plaintext).ok()
}
