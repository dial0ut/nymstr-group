use crate::{crypto_utils::CryptoUtils, db_utils::DbUtils};
use nym_sdk::mixnet::{AnonymousSenderTag, MixnetClientSender, MixnetMessageSender, ReconstructedMessage};
use redis::{AsyncCommands, aio::PubSubCommands};
use futures::StreamExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio_stream::StreamExt;
use uuid::Uuid;

/// Handler for incoming mixnet messages and command processing for group chat server.
pub struct MessageUtils {
    db: DbUtils,
    crypto: CryptoUtils,
    sender: MixnetClientSender,
    client_id: String,
    redis_client: Arc<redis::Client>,
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
        }
    }

    fn is_valid_group_name(name: &str) -> bool {
        !name.is_empty()
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
        let data: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                log::error!("JSON decode error: {}", e);
                return;
            }
        };
        if let Some(action) = data.get("action").and_then(Value::as_str) {
            match action {
                "connect" => self.handle_connect(sender_tag).await,
                "createGroup" => self.handle_create_group(&data, sender_tag).await,
                "joinGroup" => self.handle_join_group(&data, sender_tag).await,
                "inviteGroup" => self.handle_invite_group(&data, sender_tag).await,
                "approveGroup" => self.handle_approve_group(&data, sender_tag).await,
                "sendGroup" => self.handle_send_group(&data, sender_tag).await,
                _ => log::error!("Unknown action: {}", action),
            }
        } else {
            log::error!("Missing action field");
        }
    }

    async fn handle_create_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let group_name = data.get("groupName").and_then(Value::as_str);
        let is_public = data
            .get("isPublic")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let is_discoverable = data
            .get("isDiscoverable")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if group_name.is_none() || !Self::is_valid_group_name(group_name.unwrap()) {
            self.send_encapsulated_reply(
                sender_tag,
                "error: invalid group name".into(),
                "createGroupResponse",
                None,
            )
            .await;
            return;
        }
        // Identify the user
        let username = match self
            .db
            .get_user_by_sender_tag(&sender_tag.to_string())
            .await
        {
            Ok(Some((u, _, _))) => u,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: unknown user".into(),
                    "createGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        let group_id = Uuid::new_v4().to_string();
        let group_name = group_name.unwrap();
        let created = self
            .db
            .create_group(&group_id, group_name, &username, is_public, is_discoverable)
            .await
            .unwrap_or(false);
        if created {
            let _ = self
                .db
                .add_group_member(&group_id, &username, &sender_tag.to_string())
                .await;
            self.send_encapsulated_reply(
                sender_tag,
                json!({"groupId": group_id}).to_string(),
                "createGroupResponse",
                None,
            )
            .await;
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: create group failed".into(),
                "createGroupResponse",
                None,
            )
            .await;
        }
    }

    async fn handle_join_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let group_id = data.get("groupId").and_then(Value::as_str);
        if group_id.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing groupId".into(),
                "joinGroupResponse",
                None,
            )
            .await;
            return;
        }
        let group_id = group_id.unwrap();
        let username = match self
            .db
            .get_user_by_sender_tag(&sender_tag.to_string())
            .await
        {
            Ok(Some((u, _, _))) => u,
            _ => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: unknown user".into(),
                    "joinGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        if self.db.is_group_public(group_id).await.unwrap_or(false) {
            let added = self
                .db
                .add_group_member(group_id, &username, &sender_tag.to_string())
                .await
                .unwrap_or(false);
            if added {
                self.send_encapsulated_reply(
                    sender_tag,
                    "success".into(),
                    "joinGroupResponse",
                    None,
                )
                .await;
            } else {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: join group failed".into(),
                    "joinGroupResponse",
                    None,
                )
                .await;
            }
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: group is private".into(),
                "joinGroupResponse",
                None,
            )
            .await;
        }
    }

    async fn handle_invite_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let group_id = data.get("groupId").and_then(Value::as_str);
        let invitee = data.get("username").and_then(Value::as_str);
        if group_id.is_none() || invitee.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing fields".into(),
                "inviteGroupResponse",
                None,
            )
            .await;
            return;
        }
        let group_id = group_id.unwrap();
        let invitee = invitee.unwrap();
        if !self
            .db
            .is_user_admin(group_id, &sender_tag.to_string())
            .await
            .unwrap_or(false)
        {
            self.send_encapsulated_reply(
                sender_tag,
                "error: not group admin".into(),
                "inviteGroupResponse",
                None,
            )
            .await;
            return;
        }
        let invitee_tag = match self.db.get_user_by_username(invitee).await.unwrap_or(None) {
            Some((_, _, tag)) => tag,
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: user not found".into(),
                    "inviteGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        let added = self
            .db
            .add_group_invite(group_id, invitee)
            .await
            .unwrap_or(false);
        if !added {
            self.send_encapsulated_reply(
                sender_tag,
                "error: cannot invite".into(),
                "inviteGroupResponse",
                None,
            )
            .await;
            return;
        }
        let content = json!({"groupId": group_id, "inviter": sender_tag.to_string()}).to_string();
        if let Ok(recipient) = AnonymousSenderTag::try_from_base58_string(&invitee_tag) {
            let _ = self.sender.send_reply(recipient, content.clone()).await;
        }
        self.send_encapsulated_reply(sender_tag, "success".into(), "inviteGroupResponse", None)
            .await;
    }

    async fn handle_approve_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let group_id = data.get("groupId").and_then(Value::as_str);
        let user = data.get("username").and_then(Value::as_str);
        if group_id.is_none() || user.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing fields".into(),
                "approveGroupResponse",
                None,
            )
            .await;
            return;
        }
        let group_id = group_id.unwrap();
        let user = user.unwrap();
        if !self
            .db
            .is_user_admin(group_id, &sender_tag.to_string())
            .await
            .unwrap_or(false)
        {
            self.send_encapsulated_reply(
                sender_tag,
                "error: not group admin".into(),
                "approveGroupResponse",
                None,
            )
            .await;
            return;
        }
        if !self
            .db
            .is_user_invited(group_id, user)
            .await
            .unwrap_or(false)
        {
            self.send_encapsulated_reply(
                sender_tag,
                "error: user not invited".into(),
                "approveGroupResponse",
                None,
            )
            .await;
            return;
        }
        let user_tag = match self.db.get_user_by_username(user).await.unwrap_or(None) {
            Some((_, _, tag)) => tag,
            None => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: user not found".into(),
                    "approveGroupResponse",
                    None,
                )
                .await;
                return;
            }
        };
        let added = self
            .db
            .add_group_member(group_id, user, &user_tag)
            .await
            .unwrap_or(false);
        let removed = self
            .db
            .remove_group_invite(group_id, user)
            .await
            .unwrap_or(false);
        if added && removed {
            self.send_encapsulated_reply(
                sender_tag,
                "success".into(),
                "approveGroupResponse",
                None,
            )
            .await;
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: cannot approve".into(),
                "approveGroupResponse",
                None,
            )
            .await;
        }
    }

    /// Handle a client 'connect': subscribe their SURB to all group channels.
    async fn handle_connect(&mut self, sender_tag: AnonymousSenderTag) {
        let tag_str = sender_tag.to_string();
        if let Ok(groups) = self.db.get_groups_for_member(&tag_str).await {
            for group_id in groups {
                let channel = format!("group:channel:{}", group_id);
                let my_tag = tag_str.clone();
                let mixnet_sender = self.sender.clone();
                let client = self.redis_client.clone();
                tokio::spawn(async move {
                    if let Ok(mut conn) = client.get_async_connection().await {
                        let mut pubsub = conn.into_pubsub();
                        let _ = pubsub.subscribe(&channel).await;
                        let mut on_message = pubsub.on_message();
                        while let Some(msg) = on_message.next().await {
                            if let Ok(payload) = msg.get_payload::<String>() {
                                if let Ok(tag) = AnonymousSenderTag::try_from_base58_string(&my_tag) {
                                    let _ = mixnet_sender.send_reply(tag, payload.clone()).await;
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    async fn handle_send_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let group_id = data.get("groupId").and_then(Value::as_str);
        let ciphertext = data.get("ciphertext").and_then(Value::as_str);
        if group_id.is_none() || ciphertext.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing fields".into(),
                "sendGroupResponse",
                None,
            )
            .await;
            return;
        }
        let group_id = group_id.unwrap();
        let ciphertext = ciphertext.unwrap();
        let username = match self
            .db
            .get_user_by_sender_tag(&sender_tag.to_string())
            .await
        {
            Ok(Some((u, _, _))) => u,
            _ => {
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
        // publish the encrypted message exactly once into Redis Pub/Sub
        let channel = format!("group:channel:{}", group_id);
        let payload = json!({
            "groupId": group_id,
            "sender": username,
            "ciphertext": ciphertext
        })
        .to_string();
        if let Ok(mut conn) = self.redis_client.get_async_connection().await {
            let _ : Result<usize, _> = conn.publish(channel, payload).await;
        }
        self.send_encapsulated_reply(sender_tag, "success".into(), "sendGroupResponse", None)
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
