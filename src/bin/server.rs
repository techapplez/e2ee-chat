use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use futures_util::{StreamExt, SinkExt};
use tokio::sync::broadcast;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:9001").await.unwrap();
    let (tx, _) = broadcast::channel(100);

    println!("Relay server running.");

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let tx = tx.clone();
        let mut rx = tx.subscribe();

        tokio::spawn(async move {
            let ws_stream = accept_async(stream).await.unwrap();
            let (mut ws_sender, mut ws_receiver) = ws_stream.split();

            tokio::spawn(async move {
                while let Some(Ok(msg)) = ws_receiver.next().await {
                    if msg.is_binary() {
                        let _ = tx.send(msg.into_data());
                    }
                }
            });

            while let Ok(msg) = rx.recv().await {
                let _ = ws_sender.send(tungstenite::Message::Binary(msg)).await;
            }
        });
    }
}
