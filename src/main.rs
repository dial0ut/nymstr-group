mod crypto_utils;
mod db_utils;
mod log_config;
mod message_utils;

use crate::crypto_utils::CryptoUtils;
use crate::db_utils::DbUtils;
use crate::log_config::init_logging;
use crate::message_utils::MessageUtils;
use nym_sdk::mixnet::{MixnetClientBuilder, StoragePaths};
use redis::Client as RedisClient;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    let log_file = std::env::var("LOG_FILE_PATH").unwrap_or_else(|_| "logs/groupd.log".to_string());
    if let Some(parent) = PathBuf::from(&log_file).parent() {
        std::fs::create_dir_all(parent)?;
    }
    init_logging(&log_file)?;

    // Prepare database path
    let db_path =
        std::env::var("DATABASE_PATH").unwrap_or_else(|_| "storage/groupd.db".to_string());
    if let Some(parent) = PathBuf::from(&db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let db_path_buf = PathBuf::from(&db_path);
    if !db_path_buf.exists() {
        std::fs::File::create(&db_path_buf)?;
    }
    let db = DbUtils::new(&db_path).await?;

    // Prepare key storage for signing
    let keys_dir = std::env::var("KEYS_DIR").unwrap_or_else(|_| "storage/keys".to_string());
    std::fs::create_dir_all(&keys_dir)?;
    let secret_path =
        std::env::var("SECRET_PATH").unwrap_or_else(|_| "secrets/encryption_password".to_string());
    let secret_path_buf = PathBuf::from(&secret_path);
    if let Some(parent) = secret_path_buf.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !secret_path_buf.exists() {
        std::fs::write(&secret_path_buf, "")?;
    }
    let password = std::fs::read_to_string(&secret_path_buf)?
        .trim()
        .to_string();
    // Determine the client/server identity
    let client_id = std::env::var("NYM_CLIENT_ID").unwrap_or_else(|_| "groupd".to_string());
    let crypto = CryptoUtils::new(
        PathBuf::from(&keys_dir),
        client_id.clone(),
        password.clone(),
    )?;
    // Ensure the server has a PGP keypair (for signing replies).
    let pub_key_path = PathBuf::from(&keys_dir).join(format!("{}_public.asc", client_id));
    if !pub_key_path.exists() {
        log::info!(
            "Server keypair not found, generating new PGP keypair for '{}'",
            client_id
        );
        crypto.generate_key_pair(&client_id)?;
    }
    let storage_dir =
        std::env::var("NYM_SDK_STORAGE").unwrap_or_else(|_| format!("storage/{}", client_id));
    // Ensure mixnet SDK storage directory exists
    std::fs::create_dir_all(&storage_dir)?;
    let storage_paths = StoragePaths::new_from_dir(PathBuf::from(&storage_dir))?;

    // Build and connect the mixnet client
    let builder = MixnetClientBuilder::new_with_default_storage(storage_paths).await?;
    let client_inner = builder.build()?.connect_to_mixnet().await?;
    let sender = client_inner.split_sender();
    let address = client_inner.nym_address();
    log::info!("Connected to mixnet. Nym Address: {}", address);

    // process incoming messages until shutdown signal or stream end
    let mut client_stream = client_inner;

    // Connect to Redis for group pub/sub
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = Arc::new(RedisClient::open(redis_url)?);

    // Start processing incoming messages
    let mut message_utils =
        MessageUtils::new(client_id.clone(), sender, db, crypto, redis_client.clone());
    tokio::select! {
        _ = async {
            while let Some(msg) = client_stream.next().await {
                message_utils.process_received_message(msg).await;
            }
        } => {},
        _ = tokio::signal::ctrl_c() => {
            log::info!("Shutting down mixnet client.");
            client_stream.disconnect().await;
        }
    }
    Ok(())
}
