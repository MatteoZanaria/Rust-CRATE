use rustler::{Env, Term, Encoder, OwnedEnv, LocalPid};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::StreamExt;
use tokio_tungstenite::{connect_async, WebSocketStream, MaybeTlsStream};
use tokio::net::TcpStream;
use uuid::Uuid;
use url::Url;
use tokio_tungstenite::tungstenite::Message;
use futures_util::SinkExt;

#[derive(Clone)]
pub struct WebSocketManager {
    connections: Arc<Mutex<HashMap<String, (Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>, 
                                           Arc<Mutex<SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>>>)>>>,
    pids: Arc<Mutex<HashMap<String, LocalPid>>>, // HashMap per i PID associati a ciascun ID
}

impl WebSocketManager {
    pub fn new() -> Self {
        WebSocketManager {
            connections: Arc::new(Mutex::new(HashMap::new())),
            pids: Arc::new(Mutex::new(HashMap::new())), // Inizializza i PID
        }
    }

    pub async fn start_connection<'a>(&self, _env: Env<'a>, url: Url, callback: Term<'a>) -> Result<String, String> {
        let (ws_stream, _) = connect_async(url).await.map_err(|e| e.to_string())?;
        let (write, read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));
        let read = Arc::new(Mutex::new(read));
        let id = Uuid::new_v4().to_string();

        {
            let mut conn_guard = self.connections.lock().await;
            conn_guard.insert(id.clone(), (Arc::clone(&write), Arc::clone(&read)));
        }

        // Verifica se il termine è un PID e salvalo
        if let Ok(pid) = callback.decode::<LocalPid>() {
            let mut pid_guard = self.pids.lock().await;
            pid_guard.insert(id.clone(), pid);
        } else {
            return Err("(CRATE) Callback non è un PID valido".to_string());
        }

        //println!("(CRATE) WebSocket avviata ID: {} .", id.clone());

        let manager_clone = self.clone();
        let id_clone = id.clone();

        tokio::spawn(async move {
            manager_clone.listen_for_messages(id_clone).await;
        });

        Ok(id)
    }

    pub async fn listen_for_messages(&self, connection_id: String) {
        if let Some((_, read)) = self.connections.lock().await.get(&connection_id) {
            let mut read = read.lock().await;
            
            while let Some(Ok(msg)) = read.next().await {
                if let Ok(msg_text) = msg.to_text() {
                    // Usa un nuovo ambiente temporaneo per inviare il messaggio al BEAM
                    if let Some(pid) = self.pids.lock().await.get(&connection_id) {
                        let mut env = OwnedEnv::new();
                        let msg_text_clone = msg_text.to_owned();
                        
                        // Gestione del risultato con `if let` per intercettare gli errori
                        if let Err(e) = env.send_and_clear(pid, |env| {
                            let msg_term = msg_text_clone.encode(env);
                            msg_term
                        }) {
                            eprintln!("Errore nell'invio del messaggio al processo: {:?}", e);
                        }
                        
                    }
                }
            }
        }
    }

    pub async fn stop_connection(&self, id: &str) -> Result<(), String> {
        let mut conn_guard = self.connections.lock().await;
        if let Some((write, _)) = conn_guard.remove(id) {
            let mut write = write.lock().await;
            
            match write.close().await {
                Ok(_) => {
                    //println!("(CRATE) WebSocket chiusa correttamente ID: {} ", id);
                    // Rimuovi anche il PID associato
                    self.pids.lock().await.remove(id);
                    Ok(())
                }
                Err(e) => {
                    let error_message = format!("(CRATE) Errore durante la chiusura della connessione ID {}: {}", id, e);
                    eprintln!("{}", error_message);
                    Err(error_message)
                }
            }
        } else {
            let error_message = format!("(CRATE) Connessione con id {} non trovata", id);
            eprintln!("{}", error_message);
            Err(error_message)
        }
    }
    
}
