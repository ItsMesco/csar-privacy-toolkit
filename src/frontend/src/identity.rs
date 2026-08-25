use rsa::{RsaPublicKey, Oaep};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use sha2::Sha256;
use chrono::Utc;

#[derive(Serialize, Deserialize, Debug)]
pub struct InfractionIdentity{
    pub device_id: String,
    pub timestamp: u64,
}

impl InfractionIdentity{
    pub fn encrypt(&self, pub_key: &RsaPublicKey) -> Result<Vec<u8>, Box<dyn std::error::Error>>{
        let serialized_data = bincode::serialize(&self)?;
        let mut rng = OsRng;
        let padding = Oaep::new::<Sha256>();
        let ciphertext = pub_key.encrypt(&mut rng, padding, &serialized_data)?;

        Ok(ciphertext)
    }
}