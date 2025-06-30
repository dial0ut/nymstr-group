//! Example Rust CLI to test nymstr-groupd via the Nym mixnet.
//!
//! Usage:
//!   cargo run --example client -- <server_nym_address> [client_id]

use anyhow::Result;
use nym_sdk::mixnet::{
    IncludedSurbs, MixnetClientBuilder, MixnetClientSender, MixnetMessageSender, Recipient,
    StoragePaths,
};
use sequoia_openpgp::armor::Kind;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer as StreamSigner};
use sequoia_openpgp::types::HashAlgorithm;
use serde_json::{Value, json};
use std::{
    env,
    io::{self, BufRead, Write},
    path::PathBuf,
};
use tokio_stream::StreamExt;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    // ------------------------------------------------------------------
    // 1. CLI args
    // ------------------------------------------------------------------
    let mut args = env::args().skip(1);
    let server_address = args
        .next()
        .expect("Usage: cargo run --example client -- <server_nym_address> [client_id]");
    let client_id = args.next().unwrap_or_else(|| Uuid::new_v4().to_string());

    // ------------------------------------------------------------------
    // 2. Storage paths
    // ------------------------------------------------------------------
    let storage_dir = format!("storage/{client_id}");
    std::fs::create_dir_all(&storage_dir)?;
    let storage = StoragePaths::new_from_dir(PathBuf::from(&storage_dir))?;

    // ------------------------------------------------------------------
    // 3. Ephemeral OpenPGP key
    // ------------------------------------------------------------------
    let (cert, _revocation) = CertBuilder::new()
        .add_userid(client_id.clone())
        .add_signing_subkey()
        .generate()?;

    let mut keypair = cert
        .keys()
        .unencrypted_secret()
        .with_policy(&StandardPolicy::new(), None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .expect("no signing key")
        .key()
        .clone()
        .into_keypair()?;

    let public_key_armored: String = String::from_utf8(SerializeInto::to_vec(&cert.armored())?)?;

    // ------------------------------------------------------------------
    // 4. Build & connect mixnet client
    // ------------------------------------------------------------------
    let builder = MixnetClientBuilder::new_with_default_storage(storage).await?;
    let client = builder.build()?.connect_to_mixnet().await?;
    let sender: MixnetClientSender = client.split_sender();
    let mut maybe_receiver = Some(client);
    let server_recipient: Recipient = server_address.parse()?;

    // ------------------------------------------------------------------
    // 5. REPL
    // ------------------------------------------------------------------
    println!(
        "Enter commands:
  connect
  send <ciphertext>
  fetch <lastSeenId>
  exit"
    );

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let mut parts = line.splitn(3, ' ');
        match parts.next() {
            // ----------------------------------------------------------
            // CONNECT
            // ----------------------------------------------------------
            Some("connect") => {
                // a) register
                println!("-> Registering user with server…");
                let register_msg = json!({
                    "action": "register",
                    "username": client_id,
                    "publicKey": public_key_armored,
                })
                .to_string()
                .into_bytes();

                sender
                    .send_message(
                        server_recipient.clone(),
                        register_msg,
                        IncludedSurbs::Amount(10),
                    )
                    .await?;

                // Wait for registerResponse
                if let Some(mut rec) = maybe_receiver.take() {
                    while let Some(frame) = rec.next().await {
                        let txt = String::from_utf8(frame.message.clone())?;
                        let v = serde_json::from_str::<Value>(&txt)?;
                        if v.get("action").and_then(Value::as_str) == Some("registerResponse") {
                            let content = v["content"].as_str().unwrap_or("");
                            println!("RegisterResponse: {content}");
                            if content == "success" || content == "error: user already registered" {
                                break;
                            } else {
                                panic!("Register failed: {content}");
                            }
                        }
                    }

                    // b) connect with detached signature
                    println!("-> Sending connect (with PGP-signed publicKey)…");
                    // Build a proper v4 detached PGP signature packet
                    let signature_armored = {
                        let mut buf = Vec::new();
                        // ASCII-armored, detached v4 signature
                        let armor = Armorer::new(Message::new(&mut buf))
                            .kind(Kind::Signature)
                            .build()?;
                        // Create a detached signature writer_stack
                        let mut signer = StreamSigner::new(armor, keypair.clone())?
                            .detached()
                            .build()?;
                        signer.write_all(public_key_armored.as_bytes())?;
                        signer.finalize()?;
                        String::from_utf8(buf)?
                    };

                    let connect_msg = json!({
                        "action": "connect",
                        "username": client_id,
                        "publicKey": public_key_armored,
                        "signature": signature_armored,
                    })
                    .to_string()
                    .into_bytes();

                    sender
                        .send_message(
                            server_recipient.clone(),
                            connect_msg,
                            IncludedSurbs::Amount(10),
                        )
                        .await?;

                    // spawn inbound listener
                    let mut inbound = rec;
                    tokio::spawn(async move {
                        while let Some(frame) = inbound.next().await {
                            if let Ok(text) = String::from_utf8(frame.message.clone()) {
                                println!("[Inbound] {text}");
                            }
                        }
                    });
                }
            }

            // ----------------------------------------------------------
            // JOIN GROUP (no-op for single group)
            // ----------------------------------------------------------
            Some("join") => {
                // single-group server; no join action needed
            }

            // ----------------------------------------------------------
            // SEND
            // ----------------------------------------------------------
            Some("send") => {
                if let Some(cipher) = parts.next() {
                    let msg = json!({
                        "action": "sendGroup",
                        "ciphertext": cipher
                    })
                    .to_string()
                    .into_bytes();
                    sender
                        .send_message(server_recipient.clone(), msg, IncludedSurbs::Amount(10))
                        .await?;
                }
            }

            // ----------------------------------------------------------
            // FETCH
            // ----------------------------------------------------------
            Some("fetch") => {
                if let Some(last_seen) = parts.next() {
                    let msg = json!({
                        "action": "fetchGroup",
                        "lastSeenId": last_seen
                    })
                    .to_string()
                    .into_bytes();
                    sender
                        .send_message(server_recipient.clone(), msg, IncludedSurbs::Amount(10))
                        .await?;
                }
            }

            // ----------------------------------------------------------
            // EXIT
            // ----------------------------------------------------------
            Some("exit") => break,

            _ => println!("Unknown command, use: connect | join … | send … | exit"),
        }
    }

    Ok(())
}
