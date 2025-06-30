//! PGP-based key management and signing utilities using Sequoia OpenPGP 2.0.
use anyhow::{Context, Result};
use openpgp::{
    PacketPile, armor::Kind as ArmorKind, cert::prelude::*, packet::Packet, parse::Parse,
    policy::StandardPolicy, serialize::SerializeInto,
};
use sequoia_openpgp as openpgp;
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

/// Utility for PGP key generation, detached signing, and signature verification.
pub struct CryptoUtils {
    key_dir: PathBuf,
    username: String,
    password: String,
}

impl CryptoUtils {
    /// Initialize with the key directory, server username, and optional passphrase.
    pub fn new(key_dir: PathBuf, username: String, password: String) -> Result<Self> {
        if !key_dir.exists() {
            fs::create_dir_all(&key_dir)?;
        }
        Ok(Self {
            key_dir,
            username,
            password,
        })
    }

    /// Generate a new PGP certificate (with signing subkey), store secret + public armor,
    /// and return the ASCII-armored public key.
    pub fn generate_key_pair(&self, _username: &str) -> Result<String> {
        // Build a new cert with a signing subkey.
        let (cert, _revocation) = CertBuilder::new()
            .add_userid(self.username.clone())
            .add_signing_subkey()
            .generate()?;

        // Persist secret certificate (unencrypted).
        let secret_armored = String::from_utf8(cert.as_tsk().armored().to_vec()?)?;
        fs::write(
            self.key_dir.join(format!("{}_secret.asc", self.username)),
            &secret_armored,
        )?;

        // Persist public certificate.
        let public_armored = String::from_utf8(cert.armored().to_vec()?)?;
        fs::write(
            self.key_dir.join(format!("{}_public.asc", self.username)),
            &public_armored,
        )?;

        Ok(public_armored)
    }

    /// Create an ASCII-armored detached signature over `message` using the stored secret key.
    pub fn sign_message(&self, _username: &str, message: &str) -> Result<String> {
        let secret_armored =
            fs::read_to_string(self.key_dir.join(format!("{}_secret.asc", self.username)))?;
        sign_detached(&secret_armored, message)
    }

    /// Verify an ASCII-armored PGP detached signature against a PGP public key.
    pub fn verify_pgp_signature(
        &self,
        public_key_armored: &str,
        message: &str,
        signature_armored: &str,
    ) -> bool {
        log::info!(
            "verify_pgp_signature: public_key length={}, message length={}, signature length={}",
            public_key_armored.len(),
            message.len(),
            signature_armored.len()
        );
        let cert = match Cert::from_reader(public_key_armored.as_bytes()) {
            Ok(c) => c,
            Err(err) => {
                log::error!("verify_pgp_signature: parse public key: {:?}", err);
                return false;
            }
        };
        let mut reader = openpgp::armor::Reader::from_bytes(
            signature_armored.as_bytes(),
            openpgp::armor::ReaderMode::Tolerant(Some(ArmorKind::Signature)),
        );
        let mut decoded = Vec::new();
        if reader.read_to_end(&mut decoded).is_err() {
            log::error!("verify_pgp_signature: dearmor signature failed");
            return false;
        }
        // Parse the detached signature packet(s) from the decoded data.
        let pile = match PacketPile::from_bytes(&decoded) {
            Ok(p) => p,
            Err(err) => {
                log::error!(
                    "verify_pgp_signature: parse signature packet pile: {:?}",
                    err
                );
                return false;
            }
        };
        // Extract the first signature packet.
        let sig = match pile.into_children().find_map(|pkt| {
            if let Packet::Signature(s) = pkt {
                Some(s)
            } else {
                None
            }
        }) {
            Some(s) => s,
            None => {
                log::error!("verify_pgp_signature: no signature packet found");
                return false;
            }
        };
        // Verify against all signing-capable keys in the certificate.
        let policy = &StandardPolicy::new();
        for binding in cert
            .keys()
            .with_policy(policy, None)
            .supported()
            .alive()
            .for_signing()
        {
            if sig
                .verify_message(binding.key(), message.as_bytes())
                .is_ok()
            {
                return true;
            }
        }
        false
    }
}

// -----------------------------------------------------------------------------
// PGP helper – create an ASCII-armoured *detached* signature over `payload`.
// -----------------------------------------------------------------------------
fn sign_detached(secret_cert: &str, payload: &str) -> Result<String> {
    use openpgp::{
        armor::Kind as ArmorKind,
        cert::prelude::*,
        policy::StandardPolicy,
        serialize::stream::{Armorer, Message, Signer},
        types::HashAlgorithm,
    };

    // Load certificate and pick a signing-capable subkey.
    let cert = openpgp::Cert::from_reader(secret_cert.as_bytes())?;
    let policy = &StandardPolicy::new();
    let keypair = cert
        .keys()
        .secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .for_signing()
        .next()
        .context("no usable signing key")?
        .key()
        .clone()
        .into_keypair()?;

    // Armor & detach-sign.
    let mut buf = Vec::new();
    {
        let m = Message::new(&mut buf);
        let m = Armorer::new(m).kind(ArmorKind::Signature).build()?;
        let mut signer = Signer::new(m, keypair)?
            .detached()
            .hash_algo(HashAlgorithm::SHA256)?
            .build()?;
        signer.write_all(payload.as_bytes())?;
        signer.finalize()?;
    }
    Ok(String::from_utf8(buf)?)
}
