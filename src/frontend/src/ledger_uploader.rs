//! Ancoraggio esterno dei checkpoint: upload a rateo costante di una busta
//! RSA-OAEP indirizzata all'Autorità. Il provider fa solo da bacheca opaca.
use crate::local_privacy_ledger::LocalPrivacyLedger;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CheckpointPlain {
    pub seq: u64,
    pub merkle_root: [u8; 32],
    pub database_root: [u8; 32],
    pub client_ts: i64,
}

/// Riga restituita dall'endpoint di audit del backend.
#[derive(serde::Deserialize)]
pub struct CheckpointRow {
    pub seq: i64,
    pub checkpoint_ct_b64: String,
    pub received_ts: String,
}

pub struct CheckpointUploader {
    client: reqwest::Client,
    url: String,
    token: String,
    device_id: String,
    ledger_path: String,
    authority_pub: RsaPublicKey,
}

impl CheckpointUploader {
    pub fn new(
        device_id: String,
        token: &str,
        ledger_path: &str,
        authority_pub: RsaPublicKey,
    ) -> Self {
        Self {
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .expect("reqwest client"),
            url: "https://127.0.0.1:3000/api/v1/ledger/checkpoint".into(),
            token: token.to_string(),
            device_id,
            ledger_path: ledger_path.to_string(),
            authority_pub,
        }
    }

    /// Un tick di ancoraggio: rateo costante, indipendente dalle scansioni.
    pub async fn tick(
        &self,
        seq: u64,
        db_root: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ledger = LocalPrivacyLedger::open(&self.ledger_path)?;
        let root = ledger.get_latest_checkpoint()?.unwrap_or([0u8; 32]);

        let plain = CheckpointPlain {
            seq,
            merkle_root: root,
            database_root: db_root,
            client_ts: chrono::Utc::now().timestamp(),
        };
        let serialized = bincode::serialize(&plain)?;
        debug_assert!(serialized.len() <= 190, "payload RSA-OAEP 2048 troppo grande");

        let ct = self.authority_pub.encrypt(
            &mut rand::rngs::OsRng,
            Oaep::new::<Sha256>(),
            &serialized,
        )?;

        let resp = self.client
            .post(&self.url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&serde_json::json!({
                "device_id": self.device_id,
                "seq": seq,
                "checkpoint_ct_b64": BASE64.encode(&ct),
            }))
            .send()
            .await?;

        println!(
            "      [anchor] seq={:<3} ct={}… → {}",
            seq, &BASE64.encode(&ct)[..16], resp.status()
        );
        Ok(())
    }
}