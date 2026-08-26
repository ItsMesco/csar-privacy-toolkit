// backend/src/main.rs
mod server_audit;
mod zkp_circuit;

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
use zkp_circuit::HammingDistanceCircuit;

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
}

// ─── Main ─────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("⚙️ Inizializzazione Server CSAR (Provider)...");

    // Apri il ledger di audit
    let ledger = PrivacyLedger::open("server_audit.db")
        .expect("Impossibile aprire il DB del server");

    let start_event = AuditEvent::new(
        AuditEventType::DatabasePublished,
        "v1.0.0-csam-list",
        "Server avviato.",
    );
    ledger.append_event(&start_event).expect("Errore log avvio");

    // Stato condiviso (solo ledger, niente più chiavi)
    let shared_state = Arc::new(AppState {
        ledger: Arc::new(Mutex::new(ledger)),
    });

    // Router
    let app = Router::new()
        .route("/api/v1/hashes/manifest", get(get_manifest))
        .route("/api/v1/hashes/download", get(download_db))
        .route("/api/v1/scan/zkp", post(handle_zkp_scan))
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
    State(_state): State<Arc<AppState>>,
) -> Json<DbManifest> {
    info!("🔍 Richiesta Manifest ricevuta");
    Json(DbManifest {
        version: "v1.0.0-csam-list".into(),
        db_hash: "sha256-placeholder".into(),
    })
}

// ─── Handler: Download DB (già esistente) ─────────────────────
async fn download_db(
    _auth: AuthToken,
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    info!("📥 Download DB richiesto");
    let payload = serde_json::json!({
        "version": "v1.0.0-csam-list",
        "hashes": [
            "319016a7aab499193408ef3de4896df93ec84d5eea85c2e7af64726ea247ba05",
            "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"
        ]
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        payload.to_string(),
    )
}