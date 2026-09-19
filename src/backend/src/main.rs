// backend/src/main.rs
mod server_audit;
mod db_merkle;
use crate::db_merkle::*;
use axum::{
    extract::{FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tracing::info;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::{SNARK, CircuitSpecificSetupSNARK};
use rand::rngs::OsRng;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

use server_audit::{AuditEvent, AuditEventType, PrivacyLedger};
use curv::arithmetic::traits::Converter;
use kzen_paillier::{Add, BigInt, DecryptionKey, Decrypt, EncryptionKey, Encrypt, Mul, Paillier, RawCiphertext, RawPlaintext};
use std::borrow::Cow;

// ─── Auth Extractor ───────────────────────────────────────────
pub struct AuthToken;

impl<S> FromRequestParts<S> for AuthToken
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str == "Bearer super-secret-device-token-123" {
                    return Ok(AuthToken);
                }
            }
        }
        Err((
            StatusCode::UNAUTHORIZED,
            "🚫 Accesso negato: token mancante o non valido.",
        )
            .into_response())
    }
}

// ─── Payload in ingresso dal client ───────────────────────────
#[derive(Deserialize)]
struct ZkpScanPayload {
    proof_b64: String,
    verifying_key_b64: String,
    reference_hash_hex: String,
    threshold: u32,
}

// ─── Risposta al client ───────────────────────────────────────
#[derive(Serialize)]
struct ZkpScanResponse {
    valid: bool,
    message: String,
}

// ─── Stato condiviso ──────────────────────────────────────────
#[derive(Clone)]
struct AppState {
    ledger: Arc<Mutex<PrivacyLedger>>,
    db_root: [u8; 32],
}

// ─── Main ─────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("⚙️ Inizializzazione Server CSAR (Provider)...");

    // Apri il ledger di audit
    let ledger = PrivacyLedger::open("server_audit.db")
        .expect("Impossibile aprire il DB del server");

    let db = published_db();
    let db_root = db_merkle_root(&db);
    let start_event = AuditEvent::new(
        AuditEventType::DatabasePublished,
        "v1.0.0-csam-list",
        format!("root={}", hex::encode(db_root)),
    );
    ledger.append_event(&start_event).expect("Errore log avvio");

    let shared_state = Arc::new(AppState {
        ledger: Arc::new(Mutex::new(ledger)),
        db_root,
    });

    let app = Router::new()
        .route("/api/v1/hashes/manifest", get(get_manifest))
        .route("/api/v1/hashes/download", get(download_db))
        .route("/api/v1/scan/zkp", post(handle_zkp_scan))
        .route("/api/v1/scan/zkp-membership", post(handle_zkp_membership_scan))
        .route("/api/v1/scan/phe", post(handle_phe_scan))
        .with_state(shared_state);

    // Carica i certificati TLS (percorsi fissi relativi alla cartella del backend)
    let cert_path = concat!(env!("CARGO_MANIFEST_DIR"), "/certs/cert.pem");
    let key_path = concat!(env!("CARGO_MANIFEST_DIR"), "/certs/key.pem");

    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .expect("Impossibile caricare i certificati TLS");

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("🔒 Server CSAR in ascolto su https://127.0.0.1:3000 (TLS attivo)");

    // Avvia il server CON TLS (invece di axum::serve)
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// ─── Handler: Verifica ZKP ────────────────────────────────────
async fn handle_zkp_scan(
    _auth: AuthToken,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ZkpScanPayload>,
) -> impl IntoResponse {
    info!("📨 Ricevuta proof ZKP. Verifica in corso...");

    // Log: proof ricevuta
    {
        let ledger = state.ledger.lock().unwrap();
        let event = AuditEvent::new(
            AuditEventType::ProofReceived,
            "v1.0.0-csam-list",
            &format!("threshold={}", payload.threshold),
        );
        let _ = ledger.append_event(&event);
    }

    // 1. Decodifica la proof da base64
    let proof_bytes = match BASE64.decode(&payload.proof_b64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ZkpScanResponse {
                    valid: false,
                    message: format!("Decodifica proof base64 fallita: {}", e),
                }),
            );
        }
    };

    // 2. Deserializza la proof
    let proof = match Proof::<Bn254>::deserialize_compressed(&proof_bytes[..]) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ZkpScanResponse {
                    valid: false,
                    message: format!("Deserializzazione proof fallita: {}", e),
                }),
            );
        }
    };

    // 3. Decodifica la VERIFYING KEY inviata dal client
    let vk_bytes = match BASE64.decode(&payload.verifying_key_b64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ZkpScanResponse {
                    valid: false,
                    message: format!("Decodifica VK base64 fallita: {}", e),
                }),
            );
        }
    };

    let verifying_key = match VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]) {
        Ok(vk) => vk,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ZkpScanResponse {
                    valid: false,
                    message: format!("Deserializzazione Verifying Key fallita: {}", e),
                }),
            );
        }
    };

    // 4. Decodifica l'hash di riferimento
    let ref_bytes = match hex::decode(&payload.reference_hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ZkpScanResponse {
                    valid: false,
                    message: "Hash di riferimento non valido".into(),
                }),
            );
        }
    };

    // 5. Costruisci i public inputs
    let mut public_inputs: Vec<Fr> = Vec::with_capacity(257);
    for byte in ref_bytes.iter() {
        for i in (0..8).rev() {
            let b = (byte >> i) & 1 == 1;
            public_inputs.push(Fr::from(b as u64));
        }
    }
    public_inputs.push(Fr::from(payload.threshold as u64));

    // 6. Verifica la proof usando la VK del client
    let pvk = Groth16::<Bn254>::process_vk(&verifying_key)
        .expect("Errore nel processare la verifying key");

    let is_valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .unwrap_or(false);

    // 7. Log e risposta
    let event_type = if is_valid {
        AuditEventType::ProofVerified
    } else {
        AuditEventType::ProofRejected
    };

    {
        let ledger = state.ledger.lock().unwrap();
        let event = AuditEvent::new(
            event_type,
            "v1.0.0-csam-list",
            &format!("valid={}", is_valid),
        );
        let _ = ledger.append_event(&event);
    }

    if is_valid {
        info!("✅ Proof ZKP VALIDA. Match confermato.");
        (
            StatusCode::OK,
            Json(ZkpScanResponse {
                valid: true,
                message: "Proof verificata matematicamente. Match confermato.".into(),
            }),
        )
    } else {
        info!("❌ Proof ZKP RIFIUTATA.");
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ZkpScanResponse {
                valid: false,
                message: "Proof non valida. Match non confermato.".into(),
            }),
        )
    }
}

// ─── Handler: Manifest (già esistente) ────────────────────────
#[derive(Serialize)]
struct DbManifest {
    version: String,
    db_hash: String,
}

async fn get_manifest(
    _auth: AuthToken,
    State(state): State<Arc<AppState>>,
) -> Json<DbManifest> {
    info!("🔍 Richiesta Manifest ricevuta");
    Json(DbManifest {
        version: "v1.0.0-csam-list".into(),
        db_hash: hex::encode(state.db_root),
    })
}

// ─── Handler: Download DB (già esistente) ─────────────────────
async fn download_db(
    _auth: AuthToken,
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    info!("📥 Download DB richiesto");
    let hashes: Vec<String> = published_db().iter().map(hex::encode).collect();
    let payload = serde_json::json!({
        "version": "v1.0.0-csam-list",
        "hashes": hashes,
    });
    ([(header::CONTENT_TYPE, "application/json")], payload.to_string())
}

fn decode_proof_and_vk(
    proof_b64: &str,
    vk_b64: &str,
) -> Result<(Proof<Bn254>, VerifyingKey<Bn254>), String> {
    let proof_bytes = BASE64.decode(proof_b64).map_err(|e| format!("Decodifica proof base64 fallita: {}", e))?;
    let proof = Proof::<Bn254>::deserialize_compressed(&proof_bytes[..])
        .map_err(|e| format!("Deserializzazione proof fallita: {}", e))?;
    let vk_bytes = BASE64.decode(vk_b64).map_err(|e| format!("Decodifica VK base64 fallita: {}", e))?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .map_err(|e| format!("Deserializzazione Verifying Key fallita: {}", e))?;
    Ok((proof, vk))
}

#[derive(Deserialize)]
struct ZkpMembershipPayload {
    proof_b64: String,
    verifying_key_b64: String,
    threshold: u32,
}

async fn handle_zkp_membership_scan(
    _auth: AuthToken,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ZkpMembershipPayload>,
) -> impl IntoResponse {
    info!("📨 Ricevuta proof ZKP-membership. Verifica contro root pinnata...");
    {
        let ledger = state.ledger.lock().unwrap();
        let _ = ledger.append_event(&AuditEvent::new(
            AuditEventType::ProofReceived,
            "v1.0.0-csam-list",
            format!("strategy=zkp-membership threshold={}", payload.threshold),
        ));
    }

    let (proof, verifying_key) = match decode_proof_and_vk(&payload.proof_b64, &payload.verifying_key_b64) {
        Ok(x) => x,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(ZkpScanResponse { valid: false, message: msg })),
    };

    // Public inputs: 256 bit della ROOT PINNATA + threshold.
    // ⚠️ ORDINE BIT: LSB-first per byte (for i in 0..8), perché nel circuito
    // membership la root è allocata con UInt8::new_input, che alloca i bit
    // in ordine little-endian. Nell'endpoint direct-match invece è MSB-first.
    let mut public_inputs: Vec<Fr> = Vec::with_capacity(257);
    for byte in state.db_root.iter() {
        for i in 0..8 {
            let b = (byte >> i) & 1 == 1;
            public_inputs.push(Fr::from(b as u64));
        }
    }
    public_inputs.push(Fr::from(payload.threshold as u64));

    let pvk = Groth16::<Bn254>::process_vk(&verifying_key)
        .expect("Errore nel processare la verifying key");
    let is_valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .unwrap_or(false);

    let event_type = if is_valid { AuditEventType::ProofVerified } else { AuditEventType::ProofRejected };
    {
        let ledger = state.ledger.lock().unwrap();
        let _ = ledger.append_event(&AuditEvent::new(
            event_type,
            "v1.0.0-csam-list",
            format!("strategy=zkp-membership valid={}", is_valid),
        ));
    }

    if is_valid {
        info!("✅ Proof membership VALIDA: appartenenza al DB committed confermata.");
        (StatusCode::OK, Json(ZkpScanResponse {
            valid: true,
            message: "Proof verificata contro la root del database. Appartenenza confermata.".into(),
        }))
    } else {
        info!("❌ Proof membership RIFIUTATA.");
        (StatusCode::UNPROCESSABLE_ENTITY, Json(ZkpScanResponse {
            valid: false,
            message: "Proof non valida rispetto alla root del database committed.".into(),
        }))
    }
}
#[derive(Deserialize)]
struct PheScanPayload {
    ciphertexts_b64: String,
    decryption_key_b64: String, // <-- Ricevuta dal client per il test
    reference_hash_hex: String,
    threshold: u32,
}

async fn handle_phe_scan(
    _auth: AuthToken,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PheScanPayload>,
) -> impl IntoResponse {
    info!("📨 Ricevuto ciphertext PHE. Decifrazione e verifica in corso...");

    {
        let ledger = state.ledger.lock().unwrap();
        let _ = ledger.append_event(&AuditEvent::new(
            AuditEventType::ProofReceived,
            "v1.0.0-csam-list",
            format!("strategy=phe threshold={}", payload.threshold),
        ));
    }

    // 1. Decodifica e deserializza la DecryptionKey
    let dk_bytes = match BASE64.decode(&payload.decryption_key_b64) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ZkpScanResponse { valid: false, message: format!("Decodifica DK base64 fallita: {}", e) })),
    };
    let dk: DecryptionKey = match serde_json::from_slice(&dk_bytes) {
        Ok(k) => k,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ZkpScanResponse { valid: false, message: format!("Deserializzazione DK fallita: {}", e) })),
    };

    // 3. Decodifica i ciphertext
    let ct_bytes = match BASE64.decode(&payload.ciphertexts_b64) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ZkpScanResponse { valid: false, message: format!("Decodifica ciphertext base64 fallita: {}", e) })),
    };

    // 4. Ricostruisci la EncryptionKey dalla DecryptionKey
    let n = &dk.p * &dk.q;
    let nn = &n * &n;
    let ek = EncryptionKey { n, nn };

    let expected_width = ek.nn.to_bytes().len();
    let expected_total = expected_width * 256;

    // VALIDAZIONE RIGOROSA: la lunghezza deve essere ESATTAMENTE quella attesa.
    if ct_bytes.len() != expected_total {
        return (
            StatusCode::BAD_REQUEST,
            Json(ZkpScanResponse {
                valid: false,
                message: format!("Dimensione ciphertext non valida: attesi {} byte, ricevuti {} byte", expected_total, ct_bytes.len())
            }),
        );
    }

    // 5. Deserializza i 256 ciphertext in modo deterministico
    let mut cts: Vec<RawCiphertext<'static>> = Vec::with_capacity(256);
    for i in 0..256 {
        let start = i * expected_width;
        let end = start + expected_width;
        let b = &ct_bytes[start..end];
        let n_val = BigInt::from_bytes(b);
        cts.push(RawCiphertext(Cow::Owned(n_val)));
    }

    // 5. Decodifica l'hash di riferimento
    let ref_bytes = match hex::decode(&payload.reference_hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, Json(ZkpScanResponse { valid: false, message: "Hash di riferimento non valido".into() })),
    };

    // 6. Helper functions per operazioni omomorfiche con lifetime 'static
    fn clone_ct(c: &RawCiphertext<'_>) -> RawCiphertext<'static> {
        RawCiphertext(Cow::Owned(c.0.as_ref().clone()))
    }
    fn ct_add(ek: &EncryptionKey, a: RawCiphertext<'static>, b: RawCiphertext<'static>) -> RawCiphertext<'static> {
        Paillier::add(ek, a, b)
    }
    fn ct_mul_scalar(ek: &EncryptionKey, c: RawCiphertext<'static>, k: BigInt) -> RawCiphertext<'static> {
        Paillier::mul(ek, c, RawPlaintext(Cow::Owned(k)))
    }
    fn enc(ek: &EncryptionKey, v: u64) -> RawCiphertext<'static> {
        Paillier::encrypt(ek, RawPlaintext(Cow::Owned(BigInt::from(v))))
    }

    // 7. Calcolo distanza di Hamming omomorfica (identico al frontend)
    let n_minus_1 = ek.n.clone() - BigInt::from(1u32);
    let one = enc(&ek, 1);
    let mut acc = enc(&ek, 0);
    let mut idx = 0usize;

    for byte in ref_bytes.iter() {
        for i in (0..8).rev() {
            let y = (byte >> i) & 1;
            let factor = if y == 0 {
                clone_ct(&cts[idx])
            } else {
                let neg = ct_mul_scalar(&ek, clone_ct(&cts[idx]), n_minus_1.clone());
                ct_add(&ek, clone_ct(&one), neg)
            };
            acc = ct_add(&ek, acc, factor);
            idx += 1;
        }
    }

    // 8. Decifra il risultato finale
    let pt_result: RawPlaintext<'static> = Paillier::decrypt(&dk, &acc);
    let dist = pt_result.0.into_owned(); // Ottiene direttamente il BigInt

    let is_match = dist <= BigInt::from(payload.threshold as u64);

    // 9. Log e risposta
    let event_type = if is_match { AuditEventType::ProofVerified } else { AuditEventType::ProofRejected };
    {
        let ledger = state.ledger.lock().unwrap();
        let _ = ledger.append_event(&AuditEvent::new(
            event_type,
            "v1.0.0-csam-list",
            format!("strategy=phe distance={} threshold={} match={}", dist, payload.threshold, is_match),
        ));
    }

    if is_match {
        info!("✅ Distanza PHE: {} <= {} → MATCH confermato.", dist, payload.threshold);
        (StatusCode::OK, Json(ZkpScanResponse {
            valid: true,
            message: format!("Distanza di Hamming: {} (soglia: {}). Match confermato.", dist, payload.threshold),
        }))
    } else {
        info!("❌ Distanza PHE: {} > {} → NO MATCH.", dist, payload.threshold);
        (StatusCode::UNPROCESSABLE_ENTITY, Json(ZkpScanResponse {
            valid: false,
            message: format!("Distanza di Hamming: {} (soglia: {}). Nessun match.", dist, payload.threshold),
        }))
    }
}