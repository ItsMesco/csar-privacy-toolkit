mod comparison;
mod local_privacy_ledger;
mod metrics;
mod scanner;
mod identity;
mod ledger_uploader;

use comparison::{available_strategies, build_strategy, ComparisonContext,};
use hash_engine::db_merkle::{db_merkle_root, merkle_path};
use hash_engine::{compute_pdq_from_path, PdqHash};
use identity::InfractionIdentity;
use local_privacy_ledger::{ClientAuditEvent, LocalPrivacyLedger, ScanOutcome, SourceCategory};
use metrics::current_rss_kb;

use ark_std::rand::thread_rng;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use std::time::{Duration, Instant};
use std::fs;
use uuid::Uuid;
use reqwest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("==================================================");
    println!("  CSARine E2E Harness (Strategy-Agnostic)         ");
    println!("==================================================\n");

    let total_start = Instant::now();
    let ram_baseline = current_rss_kb();

    // --- FASE 0: Dati condivisi (calcolati UNA volta sola) ---
    println!("[0/4] Preparazione dati condivisi (PDQ, DB, identità)...");

    let start_hash = Instant::now();
    let local_hash = compute_pdq_from_path("../hash-engine/tests/images/test.jpg")?.0;
    let db: Vec<[u8; 32]> = vec![
        hex::decode("319016a7aab499193408ef3de4896df93ec84d5eea85c2e7af64726ea247ba05")?[..32].try_into()?,
        hex::decode("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0")?[..32].try_into()?,
    ];
    let matched_index = 0;
    let db_root = db_merkle_root(&db);
    let context = ComparisonContext {
        reference_hash: PdqHash(db[matched_index]),
        threshold: 30,
        db_root,
        merkle_path: merkle_path(&db, matched_index),
    };
    let time_hash = start_hash.elapsed();
    println!("      ✓ PDQ + dummy DB + Merkle root in {:?}", time_hash);
    println!("      ✓ DB Merkle root: {}", hex::encode(db_root));

    let start_crypto = Instant::now();
    let mut rng = thread_rng();
    let authority_priv = RsaPrivateKey::new(&mut rng, 2048)?;
    let authority_pub = RsaPublicKey::from(&authority_priv);
    let identity = InfractionIdentity {
        device_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().timestamp() as u64,
    };
    let _identity_cipher = identity.encrypt(&authority_pub)?;
    let time_crypto = start_crypto.elapsed();
    println!("      ✓ RSA-OAEP keygen + encrypt identità in {:?}", time_crypto);

    let ram_after_setup = current_rss_kb();
    println!("      ✓ RAM post-setup globale: {} KB (~{} MB)\n",
             ram_after_setup, ram_after_setup / 1024);

    // --- FASE 0.5: task di ancoraggio checkpoint (rateo costante) ---
    let device_id = identity.device_id.clone();
    let uploader = ledger_uploader::CheckpointUploader::new(
        device_id.clone(),
        "super-secret-device-token-123",
        "demo_ledger.db",
        authority_pub.clone(),
    );
    let period_secs: u64 = std::env::var("ANCHOR_PERIOD_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600); // 10 minuti in produzione
    let anchor_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(period_secs));
        let mut seq = 0u64;
        loop {
            ticker.tick().await;
            seq += 1;
            if let Err(e) = uploader.tick(seq, db_root).await {
                println!("      [anchor] upload fallito: {}", e);
            }
        }
    });
    println!("      ✓ Task di ancoraggio avviato (periodo={}s)\n", period_secs);
    // --- FASE 1: Run comparativa di TUTTE le strategie registrate ---
    println!("[1/4] Run comparativa delle strategie registrate...");
    let mut reports: Vec<StrategyReport> = Vec::new();

    for mode in available_strategies() {
        println!("\n  ▸ {}", mode);
        let run_start = Instant::now();

        // 1. Setup della strategia (keygen one-shot)
        let start_setup = Instant::now();
        let strategy = build_strategy(mode, db.len())?;
        let time_setup = start_setup.elapsed();
        println!("      setup           : {:?}", time_setup);

        // 2. Prove (compare: genera esito + proof)
        let start_zkp = Instant::now();
        let result = strategy.compare(&PdqHash(local_hash), &context)?;
        let time_zkp = start_zkp.elapsed();
        let proof_size = result.proof.as_ref().map(|p| p.len());
        println!("      prove           : {:?}  | outcome={:?}  | proof={:?} B",
                 time_zkp, result.outcome, proof_size.unwrap_or(0));

        // 3. Verify (lato server, se applicabile)
        let mut time_verify: Option<Duration> = None;
        let mut verified: Option<bool> = None;
        if let Some(proof_bytes) = &result.proof {
            let start_verify = Instant::now();
            verified = Some(strategy.verify(proof_bytes, &context)?);
            let e = start_verify.elapsed();
            time_verify = Some(e);
            println!("      verify          : {:?}  | verified={}", e, verified.unwrap());
        } else {
            println!("      verify          : ---  (no proof)");
        }

        // 4. Ledger (evento SQLite + checkpoint Merkle)
        let start_db = Instant::now();
        let ledger = LocalPrivacyLedger::open("demo_ledger.db")?;
        ledger.append_event(&ClientAuditEvent::new(
            "csar-db-v1.0",
            hex::encode(db_root),
            SourceCategory::TestFixture,
            result.outcome.clone(),
            hex::encode(local_hash),
        ))?;
        if let Some(root) = ledger.merkle_root()? {
            ledger.save_checkpoint(root)?;
        }
        let time_db = start_db.elapsed();
        println!("      ledger          : {:?}", time_db);

        // 5. Network (endpoint dedicato per ogni strategia ZKP)
        // 5. Network (endpoint dedicato per ogni strategia)
        // 5. Network (endpoint dedicato per ogni strategia)
        let mut time_net: Option<Duration> = None;
        if let Some(proof_bytes) = &result.proof {
            // Costruiamo il builder della richiesta in base alla modalità
            let req_builder = match *mode {
                "zkp" => {
                    if let Some(vk_bytes) = strategy.verifying_key_bytes() {
                        Some(reqwest::Client::builder()
                            .danger_accept_invalid_certs(true)
                            .build()?
                            .post("https://127.0.0.1:3000/api/v1/scan/zkp")
                            .json(&serde_json::json!({
                                "proof_b64": BASE64.encode(proof_bytes),
                                "verifying_key_b64": BASE64.encode(&vk_bytes),
                                "reference_hash_hex": hex::encode(context.reference_hash.0),
                                "threshold": context.threshold,
                            })))
                    } else { None }
                }
                "zkp-membership" => {
                    if let Some(vk_bytes) = strategy.verifying_key_bytes() {
                        Some(reqwest::Client::builder()
                            .danger_accept_invalid_certs(true)
                            .build()?
                            .post("https://127.0.0.1:3000/api/v1/scan/zkp-membership")
                            .json(&serde_json::json!({
                                "proof_b64": BASE64.encode(proof_bytes),
                                "verifying_key_b64": BASE64.encode(&vk_bytes),
                                "threshold": context.threshold,
                            })))
                    } else { None }
                }
                "phe" => {
                    // Per PHE, il Client invia i ciphertext e la dk (solo per questo test E2E)
                    if let Some(dk_bytes) = strategy.decryption_key_bytes() {
                        Some(reqwest::Client::builder()
                            .danger_accept_invalid_certs(true)
                            .build()?
                            .post("https://127.0.0.1:3000/api/v1/scan/phe")
                            .json(&serde_json::json!({
                                "ciphertexts_b64": BASE64.encode(proof_bytes),
                                "decryption_key_b64": BASE64.encode(&dk_bytes),
                                "reference_hash_hex": hex::encode(context.reference_hash.0),
                                "threshold": context.threshold,
                            })))
                    } else { None }
                }
                _ => None,
            };

            // Se siamo riusciti a costruire la richiesta, inviamola
            if let Some(builder) = req_builder {
                let start_net = Instant::now();
                match builder
                    .header("Authorization", "Bearer super-secret-device-token-123")
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let e = start_net.elapsed();
                        time_net = Some(e);
                        let status = resp.status();
                        if status.is_success() {
                            println!("      network (RTT)   : {:?}  | backend={}", e, status);
                        } else {
                            let err_text = resp.text().await.unwrap_or_else(|_| "<nessun corpo>".into());
                            println!("      network (RTT)   : {:?}  | backend={} | ERR: {}", e, status, err_text);
                        }
                    }
                    Err(e) => println!("      network (RTT)   : ---  (backend irraggiungibile: {})", e),
                }
            } else {
                println!("      network (RTT)   : ---  (chiavi di verifica/decifrazione mancanti)");
            }
        } else {
            println!("      network (RTT)   : ---  (no proof to send)");
        }

        let run_elapsed = run_start.elapsed();
        let ram_after_run = current_rss_kb();

        reports.push(StrategyReport {
            name: mode.to_string(),
            outcome: result.outcome,
            proof_size,
            verified,
            time_setup: Some(time_setup),
            time_zkp,
            time_verify,
            time_db,
            time_net,
            time_total: run_elapsed,
            ram_after: ram_after_run as u64,
        });
    }

    // --- FASE 2: Misurazioni finali ---
    let ram_peak = current_rss_kb();
    let db_size = fs::metadata("demo_ledger.db").map(|m| m.len()).unwrap_or(0);

    // --- REPORT FINALE ---
    println!("\n==================================================");
    println!("          STRATEGY COMPARISON REPORT              ");
    println!("==================================================");
    for r in &reports {
        println!("▸ {}", r.name);
        println!("    outcome           : {:?}", r.outcome);
        if let Some(sz) = r.proof_size {
            println!("    proof size        : {} B", sz);
        } else {
            println!("    proof size        : ---");
        }
        if let Some(v) = r.verified {
            println!("    verified          : {}", v);
        } else {
            println!("    verified          : ---");
        }
        if let Some(s) = r.time_setup {
            println!("    setup (one-shot)  : {:?}", s);
        }
        println!("    prove (per scan)  : {:?}", r.time_zkp);
        if let Some(v) = r.time_verify {
            println!("    verify (server)   : {:?}", v);
        }
        println!("    ledger (local)    : {:?}", r.time_db);
        if let Some(n) = r.time_net {
            println!("    network RTT       : {:?}", n);
        }
        println!("    TOTAL (run)       : {:?}", r.time_total);
        println!("    RAM after run     : {} KB (~{} MB)", r.ram_after, r.ram_after / 1024);
        println!("--------------------------------------------------");
    }

    println!("* PDQ hashing (shared)       : {:?}", time_hash);
    println!("* RSA-OAEP (one-shot)        : {:?}", time_crypto);
    println!("* TEMPO TOTALE (E2E)         : {:?}", total_start.elapsed());
    println!("==================================================");
    println!("* RAM Iniziale (OS base)     : {} KB (~{} MB)", ram_baseline, ram_baseline / 1024);
    println!("* RAM Post-Setup globale     : {} KB (~{} MB)", ram_after_setup, ram_after_setup / 1024);
    println!("* RAM Picco / Finale         : {} KB (~{} MB)", ram_peak, ram_peak / 1024);
    println!("* Spazio Disco SQLite        : {} Bytes (~{} KB)", db_size, db_size / 1024);
    println!("==================================================\n");

    // --- FASE 3: demo ancoraggio + audit dell'Autorità ---
    println!("\n[2/4] Attesa di 2 tick di ancoraggio a rateo costante...");
    tokio::time::sleep(std::time::Duration::from_secs(period_secs * 2 + 1)).await;
    anchor_handle.abort();

    println!("\n[3/4] Audit: l'Autorità decifra i checkpoint ancorati sul server...");
    let audit_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let url = format!(
        "https://127.0.0.1:3000/api/v1/ledger/checkpoints?device_id={}",
        device_id
    );

    let resp = audit_client
        .get(&url)
        .header("Authorization", "Bearer super-secret-device-token-123")
        .send()
        .await?;
    let rows: Vec<ledger_uploader::CheckpointRow> = resp.json().await?;

    let mut last_root: Option<[u8; 32]> = None;
    for row in &rows {
        let ct = BASE64.decode(&row.checkpoint_ct_b64)?;
        let plain_bytes = authority_priv.decrypt(Oaep::new::<sha2::Sha256>(), &ct)?;
        let cp: ledger_uploader::CheckpointPlain = bincode::deserialize(&plain_bytes)?;
        println!(
            "      [audit] seq={:<3} root={}… anchored_ts={}",
            cp.seq,
            &hex::encode(cp.merkle_root)[..8],
            row.received_ts
        );
        last_root = Some(cp.merkle_root);
    }

    let local_root = LocalPrivacyLedger::open("demo_ledger.db")?.get_latest_checkpoint()?;
    match (last_root, local_root) {
        (Some(anchored), Some(local)) if anchored == local => {
            println!("      ✓ Storia ancorata coerente con l'ultimo checkpoint locale");
        }
        _ => {
            println!("      ✗ INCOERENZA: root ancorate e ledger locale non coincidono");
        }
    }
    println!("==================================================\n");

    Ok(())
}

struct StrategyReport {
    name: String,
    outcome: ScanOutcome,
    proof_size: Option<usize>,
    verified: Option<bool>,
    time_setup: Option<Duration>,
    time_zkp: Duration,
    time_verify: Option<Duration>,
    time_db: Duration,
    time_net: Option<Duration>,
    time_total: Duration,
    ram_after: u64,
}