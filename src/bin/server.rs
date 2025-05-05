use std::{fs::File, io::{Read, Write}, path::Path, sync::Arc};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::{broadcast, Mutex}};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures_util::{StreamExt, SinkExt};

const SHARED_SECRET: &[u8; 32] = b"iamaratfanandilikerustandidkwhat";
const CREDENTIALS_FILE: &str = "credentials.json";

#[derive(Serialize, Deserialize)]
struct EncryptedMessage {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct Credential {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Default)]
struct CredentialDB {
    credentials: Vec<Credential>,
}

#[derive(Serialize, Deserialize, Default)]
struct CheckLogin {
    username: String,
    password: String,
}

fn load_db() -> CredentialDB {
    if Path::new(CREDENTIALS_FILE).exists() {
        let mut file = File::open(CREDENTIALS_FILE).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        CredentialDB::default()
    }
}

fn save_db(db: &CredentialDB) {
    let data = serde_json::to_string_pretty(db).unwrap();
    let mut file = File::create(CREDENTIALS_FILE).unwrap();
    file.write_all(data.as_bytes()).unwrap();
}

fn decrypt_message(data: &[u8]) -> Option<String> {
    let msg: EncryptedMessage = serde_json::from_slice(data).ok()?;
    let nonce = general_purpose::STANDARD.decode(&msg.nonce).ok()?;
    let ciphertext = general_purpose::STANDARD.decode(&msg.ciphertext).ok()?;
    let cipher = Aes256Gcm::new(Key::from_slice(SHARED_SECRET));
    let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref()).ok()?;
    String::from_utf8(plaintext).ok()
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:9001").await.unwrap();
    let (tx, _) = broadcast::channel(100);
    let db = Arc::new(Mutex::new(load_db()));

    while let Ok((stream, _)) = listener.accept().await {
        let tx2 = tx.clone();
        let mut rx = tx2.subscribe();
        let db = db.clone();

        tokio::spawn(async move {
            let ws = accept_async(stream).await.unwrap();
            let (mut ws_tx, mut ws_rx) = ws.split();

            tokio::spawn(async move {
                while let Some(Ok(msg)) = ws_rx.next().await {
                    if let Message::Binary(data) = msg {
                        if let Some(json) = decrypt_message(&data) {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                                if let (Some(user), Some(pass)) =
                                    (v["username"].as_str(), v["password"].as_str())
                                {
                                    let mut db = db.lock().await;
                                    if !db.credentials.iter().any(|c| c.username == user) {
                                        let passwdord = pass.to_string(); 
                                        db.credentials.push(Credential {
                                            username: user.to_string(),
                                            password: passwdord,
                                        });
                                        save_db(&db);
                                    }
                                }
                            }
                        }
                        let _ = tx2.send(data);
                    }
                }
            });

            while let Ok(data) = rx.recv().await {
                let _ = ws_tx.send(Message::Binary(data)).await;
            }
        });
    }
}

