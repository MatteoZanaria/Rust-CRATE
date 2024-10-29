use rustler::{Env, Term, Encoder, OwnedEnv, LocalPid}; 
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::UdpSocket;
use uuid::Uuid;
use std::net::{SocketAddr, AddrParseError};
use sha1::{Sha1, Digest};
use hex;
use tokio::task;

#[derive(Clone)]
pub struct SipClient {
    connections: Arc<Mutex<HashMap<String, (Option<Arc<UdpSocket>>, Option<SocketAddr>, Option<LocalPid>)>>>, // Salva <ID, (Udp||Tcp_Client_Socket_Handle, Server_Addr, PID)>
}

impl SipClient {
    pub fn new() -> Self {
        SipClient {
            connections: Arc::new(Mutex::new(HashMap::new())), // Inizializza la HashMap combinata
        }
    }

    // Funzione per stabilire la connessione e generare un ID unico
    pub async fn connect(&self, local_addr: &str, transport: &str) -> Result<String, String> {
        // 1) *** CONFIG PROTOCOLLO di trasporto (UDP o TCP) *** ---------------------------------------------------------------------------------------
        let socket = match transport.to_lowercase().as_str() {
            "tcp" => UdpSocket::bind(local_addr).await.map_err(|e| e.to_string())?,
            "udp" => UdpSocket::bind(local_addr).await.map_err(|e| e.to_string())?,
            _ => return Err("Transporto non valido; usa 'tcp' o 'udp'".to_string()),
        };
        let socket = Arc::new(socket); // Restituisce il socket come Arc per la condivisione
        let id = Uuid::new_v4().to_string();

        // Salva temporaneamente solo il socket con ID specificato
        let mut conn_guard = self.connections.lock().await;
        conn_guard.insert(id.clone(), (Some(socket), None, None));
        
        Ok(id) // Restituisce l'ID generato al client
    }

    // Funzione per effettuare la registrazione
    pub async fn register<'a>(&self, id: &str, server_addr: &str, username: &str, domain: &str, password: &str) -> Result<(), String> {
        let server_addr: SocketAddr = format!("{}:{}", server_addr, 5060).parse().map_err(|e: AddrParseError| e.to_string())?;

        // 2) *** BUILD REGISTER.Req con autenticazione *** -----------------------------------------------------------------------------------------
        let call_id = id.to_string(); // Usa direttamente `id` come Call-ID
        let cseq = 1;
        let tag = Uuid::new_v4().to_string();

        // Genera l'hash per l'autenticazione
        let ha1 = format!("{}:{}:{}", username, "voismart.it", password);
        let ha1 = Sha1::digest(ha1.as_bytes());
        let ha1 = hex::encode(ha1);

        let ha2 = format!("REGISTER:sip:{}", domain);
        let ha2 = Sha1::digest(ha2.as_bytes());
        let ha2 = hex::encode(ha2);

        let response = format!("{}:{}:{}", ha1, "nonce_from_server", ha2);
        let response = Sha1::digest(response.as_bytes());
        let response = hex::encode(response);

        let register_request = format!(
            "REGISTER sip:{} SIP/2.0\r\n\
            Via: SIP/2.0/UDP {}\r\n\
            To: <sip:{}@{}>\r\n\
            From: <sip:{}@{}>;tag={}\r\n\
            Call-ID: {}\r\n\
            CSeq: {} REGISTER\r\n\
            Contact: <sip:{}@{}>\r\n\
            Max-Forwards: 70\r\n\
            Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"nonce_from_server\", uri=\"sip:{}\", response=\"{}\"\r\n\
            Content-Length: 0\r\n\r\n",
            domain, server_addr, username, domain, username, domain, tag, call_id, cseq, username, server_addr, username, "voismart.it", domain, response
        );

        // 3) *** SEND REGISTER.Req *** -------------------------------------------------------------------------------------------------------------
        let mut conn_guard = self.connections.lock().await;
        if let Some((Some(socket), _, _)) = conn_guard.get(id) {
            socket.send_to(register_request.as_bytes(), &server_addr).await.map_err(|e| e.to_string())?;
        } else {
            return Err("Connessione non trovata per invio di REGISTER.".to_string());
        }

        // 4) *** RECEIVE REGISTER.Req.Response *** -------------------------------------------------------------------------------------------------------
        let mut buf = [0; 1024];
        let socket_clone = conn_guard.get(id).unwrap().0.clone().unwrap(); // Borrow immutabile per clonare il socket
        let (len, _) = socket_clone.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
        let response = String::from_utf8_lossy(&buf[..len]);

        println!("Risposta dal server SIP: {}", response);

        // 5) *** CHECK Response : IF (REGISTER.Req.Response == 200 OK) *** ----------------------------------------------------------------------------
        if response.contains("200 OK") {
            // Salva l'indirizzo del server, completando la registrazione, senza il callback PID
            conn_guard.insert(id.to_string(), (Some(socket_clone), Some(server_addr), None));
            Ok(())
        } else {
            Err("(CRATE) Registrazione fallita".to_string())
        }
    }

    // Funzione per inviare la richiesta SUBSCRIBE e ascoltare i messaggi NOTIFY
    pub async fn subscribe_event(&self, id: &str, local_addr: &str, transport: &str, username: &str, domain: &str, callback: Term<'_>) -> Result<(), String> {
        
        // Cerca il socket e il server address associati all'ID
        let mut conn_guard = self.connections.lock().await;
        if let Some((Some(socket), Some(server_addr), _)) = conn_guard.get(id) {

            // 0) *** Decodifica il PID per la callback e lo salva *** -----------------------------------------------------------------------------------
            let pid = callback.decode::<LocalPid>().map_err(|_| "PID non valido".to_string())?;
            let socket_clone = socket.clone();
            let server_addr_copy = *server_addr;
            conn_guard.insert(id.to_string(), (Some(socket_clone.clone()), Some(server_addr_copy), Some(pid.clone())));

            // 1) *** BUILD SUBSCRIBE.Req  *** -----------------------------------------------------------------------------------------------------------
            let call_id = Uuid::new_v4().to_string();
            let cseq = 2; // Incrementa il cseq per la richiesta SUBSCRIBE
            let tag = Uuid::new_v4().to_string();

            let subscribe_request = format!(
                "SUBSCRIBE sip:{} SIP/2.0\r\n\
                Via: SIP/2.0/{transport} {}\r\n\
                To: <sip:{}@{}>\r\n\
                From: <sip:{}@{}>;tag={}\r\n\
                Call-ID: {}\r\n\
                CSeq: {} SUBSCRIBE\r\n\
                Contact: <sip:{}@{}>\r\n\
                Max-Forwards: 70\r\n\
                Event: dialog\r\n\
                Content-Length: 0\r\n\r\n",
                domain, local_addr, username, domain, username, domain, tag, call_id, cseq, username, local_addr
            );

            // 2) *** SEND SUBSCRIBE.Req  *** ------------------------------------------------------------------------------------------------------------
            socket_clone.send_to(subscribe_request.as_bytes(), &server_addr_copy).await.map_err(|e| e.to_string())?;
            println!("Inviata richiesta SUBSCRIBE per evento 'dialog'.");

            // 3) *** AVVIO TASK PERPETUO DI ASCOLTO MESSAGGI NOTIFY *** ---------------------------------------------------------------------------------
            let connection_id = id.to_string();
            let pid = pid.clone();

            task::spawn(async move {
                if let Err(e) = Self::listen_for_messages(socket_clone, connection_id, pid).await {
                    eprintln!("Errore durante l'ascolto dei messaggi: {:?}", e);
                }
            });

            Ok(())
        } else {
            Err("(CRATE) Connessione non trovata per l'ID specificato".to_string())
        }
    }

    // Funzione per ascoltare i messaggi NOTIFY e inviarli al client Elixir
    async fn listen_for_messages(socket: Arc<UdpSocket>, _connection_id: String, pid: LocalPid) -> Result<(), String> {
        let mut buf = [0; 1024];

        loop {
            let (len, _) = socket.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
            let msg = String::from_utf8_lossy(&buf[..len]);

            // Usa un nuovo ambiente temporaneo per inviare il messaggio al BEAM
            let mut env = OwnedEnv::new();
            let msg_text_clone = msg.to_string();

            env.send_and_clear(&pid, |env| {
                let msg_term = msg_text_clone.encode(env);
                msg_term
            }).map_err(|e| format!("Errore nell'invio del messaggio al processo: {:?}", e))?;
        }
    }
}
