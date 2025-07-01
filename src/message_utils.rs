use crate::{crypto_utils::CryptoUtils, db_utils::DbUtils};
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClientSender, MixnetMessageSender, ReconstructedMessage,
};
use redis::AsyncCommands;
use serde_json::{Value, json};
use std::{collections::HashMap, env, sync::Arc};
use tokio_stream::StreamExt;

/// Handler for incoming mixnet messages and command processing for group chat server.
pub struct MessageUtils {
    db: DbUtils,
    crypto: CryptoUtils,
    sender: MixnetClientSender,
    client_id: String,
    redis_client: Arc<redis::Client>,
    /// Currently active clients: sender tags mapped to username
    active_clients: HashMap<AnonymousSenderTag, String>,
}

impl MessageUtils {
    /// Create a new MessageUtils instance.
    /// Create a new MessageUtils instance with Redis client for pub/sub.
    pub fn new(
        client_id: String,
        sender: MixnetClientSender,
        db: DbUtils,
        crypto: CryptoUtils,
        redis_client: Arc<redis::Client>,
    ) -> Self {
        MessageUtils {
            db,
            crypto,
            sender,
            client_id,
            redis_client,
            active_clients: HashMap::new(),
        }
    }

    /// Process an incoming mixnet message.
    pub async fn process_received_message(&mut self, msg: ReconstructedMessage) {
        let sender_tag = if let Some(tag) = msg.sender_tag {
            tag
        } else {
            log::warn!("Received message without sender tag, ignoring");
            return;
        };

        let raw = match String::from_utf8(msg.message) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Invalid UTF-8 in message: {}", e);
                return;
            }
        };
        log::info!("Incoming raw message from {}: {}", sender_tag, raw);
        let data: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                log::error!("JSON decode error: {}", e);
                return;
            }
        };
        log::info!("Parsed JSON message from {}: {}", sender_tag, data);
        if let Some(action) = data.get("action").and_then(Value::as_str) {
            match action {
                // Step 1: new user registration
                "register" => self.handle_register(&data, sender_tag).await,

                // Step 2: approve pending registration (admin only)
                "approveGroup" => self.handle_approve_group(&data, sender_tag).await,

                // Step 3: existing user connects
                "connect" => self.handle_connect(&data, sender_tag).await,

                // Step 4: client sends a group message (Redis Streams + push)
                "sendGroup" => self.handle_send_group(&data, sender_tag).await,
                // Step 5: client fetches new group messages (Redis Streams + pull)
                "fetchGroup" => self.handle_fetch_group(&data, sender_tag).await,
                _ => log::error!("Unknown action: {}", action),
            }
        }
    }

    /// Handle a client 'register': store their username + public key.
    async fn handle_register(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let username = match data.get("username").and_then(Value::as_str) {
            Some(u) if !u.is_empty() => u,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid username".into(),
                    "registerResponse",
                    None,
                )
                .await;
                return;
            }
        };
        // The PGP public key (ASCII-armored) to register
        let pubkey_armored = match data.get("publicKey").and_then(Value::as_str) {
            Some(pk) if !pk.is_empty() => pk,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid publicKey".into(),
                    "registerResponse",
                    None,
                )
                .await;
                return;
            }
        };
        // Verify signature over the provided public key
        let signature = match data.get("signature").and_then(Value::as_str) {
            Some(sig) if !sig.is_empty() => sig,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid signature".into(),
                    "registerResponse",
                    None,
                )
                .await;
                return;
            }
        };
        if !self
            .crypto
            .verify_pgp_signature(pubkey_armored, pubkey_armored, signature)
        {
            self.send_encapsulated_reply(
                sender_tag,
                "error: bad signature".into(),
                "registerResponse",
                None,
            )
            .await;
            return;
        }
        // Record the pending join request
        match self.db.add_pending_user(username, pubkey_armored).await {
            Ok(true) => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "pending".into(),
                    "registerResponse",
                    None,
                )
                .await;
            }
            Ok(false) => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: user already registered".into(),
                    "registerResponse",
                    None,
                )
                .await;
            }
            Err(e) => {
                log::error!("DB error during register: {}", e);
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: registration failed".into(),
                    "registerResponse",
                    None,
                )
                .await;
            }
        }
    }

    /// Handle a client 'approveGroup': verify admin signature and approve pending user.
    async fn handle_approve_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let username = match data.get("username").and_then(Value::as_str) {
            Some(u) if !u.is_empty() => u,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: unauthorized or bad signature".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        let signature = match data.get("signature").and_then(Value::as_str) {
            Some(sig) if !sig.is_empty() => sig,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: unauthorized or bad signature".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        let admin_key = env::var("ADMIN_PK").unwrap_or_default();
        if admin_key.is_empty()
            || !self
                .crypto
                .verify_pgp_signature(&admin_key, username, signature)
        {
            self.send_encapsulated_reply(
                sender_tag,
                "error: unauthorized or bad signature".into(),
                "approveGroupResponse",
                None,
            )
            .await;
            return;
        }
        // Fetch pending registration data
        let pubkey = match self.db.get_pending_user(username).await {
            Ok(Some(pk)) => pk,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: approve failed".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        // Approve user: add to users table
        match self.db.add_user(username, &pubkey).await {
            Ok(true) => {
                let _ = self.db.remove_pending_user(username).await;
                self.send_encapsulated_reply(
                    sender_tag,
                    "success".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
            }
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: approve failed".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
            }
        }
    }

    /// Handle a client 'connect': verify signature, authenticate, and subscribe to group channel.
    async fn handle_connect(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let username = match data.get("username").and_then(Value::as_str) {
            Some(u) if !u.is_empty() => u,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid username".into(),
                    "connectResponse",
                    None,
                )
                .await;
                return;
            }
        };
        let signature = match data.get("signature").and_then(Value::as_str) {
            Some(sig) if !sig.is_empty() => sig,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid signature".into(),
                    "connectResponse",
                    None,
                )
                .await;
                return;
            }
        };
        // Verify user is approved and retrieve their public key
        let public_key = match self.db.get_user_by_username(username).await {
            Ok(Some((_u, pubkey))) => pubkey,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: user not registered or not approved".into(),
                    "connectResponse",
                    None,
                )
                .await;
                return;
            }
        };
        // Verify detached signature over the username
        if !self
            .crypto
            .verify_pgp_signature(&public_key, username, signature)
        {
            self.send_encapsulated_reply(
                sender_tag,
                "error: bad signature".into(),
                "connectResponse",
                None,
            )
            .await;
            return;
        }
        // Mark sender as an active client
        self.active_clients.insert(sender_tag, username.to_string());
        // Send success response
        self.send_encapsulated_reply(sender_tag, "success".into(), "connectResponse", None)
            .await;
        // Subscribe to the single group channel for incoming messages
        let tag_str = sender_tag.to_string();
        let channel = "group:channel";
        let my_tag = tag_str.clone();
        let mixnet_sender = self.sender.clone();
        let client = self.redis_client.clone();
        tokio::spawn(async move {
            if let Ok(conn) = client.get_async_connection().await {
                let mut pubsub = conn.into_pubsub();
                let _ = pubsub.subscribe(channel).await;
                let mut on_message = pubsub.on_message();
                while let Some(msg) = on_message.next().await {
                    if let Ok(payload) = msg.get_payload::<String>() {
                        if let Ok(tag) = AnonymousSenderTag::try_from_base58_string(&my_tag) {
                            let _ = mixnet_sender.send_reply(tag, payload).await;
                        }
                    }
                }
            }
        });
    }

    async fn handle_send_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let ciphertext = data.get("ciphertext").and_then(Value::as_str);
        if ciphertext.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing ciphertext".into(),
                "sendGroupResponse",
                None,
            )
            .await;
            return;
        }
        let ciphertext = ciphertext.unwrap();
        let username = match self.active_clients.get(&sender_tag) {
            Some(u) => u.clone(),
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: unknown user".into(),
                    "sendGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        // push the encrypted message into Redis Stream for pull-based fan-out
        let stream_key = "group:stream";
        let payload = json!({
            "sender": username,
            "ciphertext": ciphertext
        })
        .to_string();
        if let Ok(mut conn) = self.redis_client.get_async_connection().await {
            // XADD <stream_key> * message <payload>
            let _: Result<String, _> = conn
                .xadd(&stream_key, "*", &[("message", payload.as_str())])
                .await;
        }
        self.send_encapsulated_reply(sender_tag, "success".into(), "sendGroupResponse", None)
            .await;
    }

    /// Handle a client request to fetch new group messages (Redis Streams + pull)
    async fn handle_fetch_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        // Extract and verify signature over lastSeenId
        let last_seen = match data.get("lastSeenId").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => s,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid lastSeenId".into(),
                    "fetchGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        let signature = match data.get("signature").and_then(Value::as_str) {
            Some(sig) if !sig.is_empty() => sig,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: missing or invalid signature".into(),
                    "fetchGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        // Verify signature against registered public key
        let username = match self.active_clients.get(&sender_tag) {
            Some(u) => u.clone(),
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: user not registered or not approved".into(),
                    "fetchGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        let public_key = match self.db.get_user_by_username(&username).await {
            Ok(Some((_u, pk))) => pk,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: user not registered or not approved".into(),
                    "fetchGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        if !self
            .crypto
            .verify_pgp_signature(&public_key, last_seen, signature)
        {
            self.send_encapsulated_reply(
                sender_tag,
                "error: bad signature".into(),
                "fetchGroupResponse",
                None,
            )
            .await;
            return;
        }
        // Read new entries from the Redis Stream for the single group
        let stream_key = "group:stream";
        let mut msgs = Vec::new();
        if let Ok(mut conn) = self.redis_client.get_async_connection().await {
            // Non-blocking XREAD from last_seen
            if let Ok(reply) = conn
                .xread::<_, _, Vec<redis::streams::StreamReadReply>>(&[&stream_key], &[last_seen])
                .await
            {
                for stream in reply {
                    for sk in stream.keys {
                        for entry in sk.ids {
                            // entry.id is the message ID
                            // entry.map contains field-value pairs
                            if let Some(redis::Value::Data(bytes)) = entry.map.get("message") {
                                if let Ok(s) = String::from_utf8(bytes.clone()) {
                                    msgs.push((s, entry.id.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }
        // Send back all new messages
        let content = json!({
            "messages": msgs    // Vec<(ciphertext, messageId)>
        })
        .to_string();
        self.send_encapsulated_reply(sender_tag, content, "fetchGroupResponse", None)
            .await;
    }

    /// Sign and send a JSON reply over the mixnet using SURBs.
    async fn send_encapsulated_reply(
        &self,
        recipient: AnonymousSenderTag,
        content: String,
        action: &str,
        context: Option<&str>,
    ) {
        let mut payload = json!({"action": action, "content": content});
        if let Some(ctx) = context {
            payload["context"] = json!(ctx);
        }
        let to_sign = payload["content"].as_str().unwrap_or_default().to_string();
        if let Ok(signature) = self.crypto.sign_message(&self.client_id, &to_sign) {
            payload["signature"] = json!(signature);
            let msg = payload.to_string();
            let _ = self.sender.send_reply(recipient, msg).await;
        } else {
            log::error!("sendEncapsulatedReply - failed to sign message");
        }
    }
}
