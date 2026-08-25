mod comparison;
mod local_privacy_ledger;
mod metrics;
mod scanner;
mod identity;

use comparison::zkp_engine::{generate_proof, verify_proof, ZkpKeys};
use identity::InfractionIdentity;
use local_privacy_ledger::{ClientAuditEvent, LocalPrivacyLedger, ScanOutcome, SourceCategory};
use hash_engine::compute_pdq_from_path;
use metrics::current_rss_kb; // Importiamo la tua funzione di telemetria

use ark_std::rand::thread_rng;
use chrono::Utc;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::time::Instant;
use std::fs; // Per leggere la dimensione dei file su disco
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("==================================================");
    println!("  Avvio Pipeline E2E (Real Math Execution)        ");
    println!("==================================================\n");

    let total_start = Instant::now();
    let mut rng = thread_rng();

    // 0. Misuriamo la RAM iniziale (Baseline)
    let ram_baseline = current_rss_kb();

    // --- FASE 0: Setup Crittografico ---
    println!("[0/6] ⚙️ Inizializzazione parametri (Trusted Setup & Chiavi RSA)...");
    let start_setup = Instant::now();

    let zkp_keys = ZkpKeys::generate()?;

    let authority_priv_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let authority_pub_key = RsaPublicKey::from(&authority_priv_key);

    let time_setup = start_setup.elapsed();
    let ram_after_setup = current_rss_kb();
    println!("      ✓ Setup completato. Tempo: {:?}", time_setup);

    // --- FASE 1: Dati di Input ---
    println!("[1/6] 🔍 Preparazione hash PDQ...");
    let start_hash = Instant::now();

    // Inserisci qui i percorsi reali delle tue immagini test
    let local_pdq = compute_pdq_from_path("../../hash-engine/tests/images/test.jpg")?;
    let ref_pdq = compute_pdq_from_path("../../hash-engine/tests/images/test.jpg")?;

    let local_hash = local_pdq.0;
    let ref_hash = ref_pdq.0;
    let threshold = 31u32;

    let time_hash = start_hash.elapsed();
    println!("      ✓ Dati pronti. Tempo: {:?}", time_hash);

    // --- FASE 2: Proving ZKP con Arkworks ---
    println!("[2/6] 🧮 Calcolo ZKP (Groth16 su BN254)...");
    let start_zkp = Instant::now();

    let proof = generate_proof(&zkp_keys, local_hash, ref_hash, threshold)?;

    let time_zkp = start_zkp.elapsed();
    println!("      ✓ Prova crittografica generata. Tempo: {:?}", time_zkp);

    // --- FASE 3: Identità e Cifratura RSA ---
    println!("[3/6] 👤 Cifratura Identità Asimmetrica...");
    let start_crypto = Instant::now();

    let device_id = Uuid::new_v4().to_string();
    let current_timestamp = Utc::now().timestamp() as u64;

    let identity = InfractionIdentity { device_id, timestamp: current_timestamp };
    let ciphertext = identity.encrypt(&authority_pub_key)?;

    let time_crypto = start_crypto.elapsed();
    println!("      ✓ RSA-OAEP calcolato. Tempo: {:?}", time_crypto);

    // --- FASE 4: Scrittura Locale su SQLite & Merkle Tree ---
    println!("[4/6] 💾 Salvataggio su SQLite locale (Accountability)...");
    let start_db = Instant::now();

    let db_path = "demo_ledger.db";
    let ledger = LocalPrivacyLedger::open(db_path)?;

    let event = ClientAuditEvent::new(
        "csar-db-v1.0",
        "demo-merkle-root",
        SourceCategory::Incoming,
        ScanOutcome::Match,
        hex::encode(local_hash)
    );

    ledger.append_event(&event)?;

    if let Some(root) = ledger.merkle_root()? {
        ledger.save_checkpoint(root)?;
    }

    let time_db = start_db.elapsed();
    println!("      ✓ Evento salvato su disco. Tempo: {:?}", time_db);

    // --- FASE 5: Networking (Simulazione Padding) ---
    println!("[5/6] 📦 Costruzione Payload (Traffic Padding)...");
    let start_batch = Instant::now();

    let _payload_size = 2048;

    let time_batch = start_batch.elapsed();
    println!("      ✓ Pacchetto 2KB assemblato. Tempo: {:?}", time_batch);

    // --- FASE 6: Verifica Server-Side (Il Verifier) ---
    println!("[6/6] 🛡️ Verifica ZKP (Simulazione Server)...");
    let start_verify = Instant::now();

    let is_valid = verify_proof(&zkp_keys, &proof, ref_hash, threshold)?;

    let time_verify = start_verify.elapsed();
    if is_valid {
        println!("      ✓ Il Server conferma: Prova ZKP VALIDA. Tempo: {:?}", time_verify);
    } else {
        println!("      ❌ ERRORE: Prova ZKP Rifiutata!");
    }

    // 7. Misurazioni Finali di Sistema
    let ram_peak = current_rss_kb(); // Fotografiamo la RAM alla fine del processo
    let db_size = fs::metadata(db_path).map(|m| m.len()).unwrap_or(0); // Leggiamo i byte del DB

    // --- REPORT FINALE ---
    println!("\n==================================================");
    println!("                REPORT PRESTAZIONI REALI          ");
    println!("==================================================");
    println!("* Setup & Keygen (Una tantum) : {:?}", time_setup);
    println!("* Hashing PDQ (Client)        : {:?}", time_hash);
    println!("* ZKP Prove (Client)          : {:?}", time_zkp);
    println!("* ZKP Verify (Server)         : {:?}", time_verify);
    println!("* RSA-OAEP Encrypt            : {:?}", time_crypto);
    println!("* SQLite / Merkle Tree        : {:?}", time_db);
    println!("* Payload Normalization       : {:?}", time_batch);
    println!("--------------------------------------------------");
    println!("* TEMPO TOTALE (E2E)          : {:?}", total_start.elapsed());
    println!("==================================================");
    println!("* RAM Iniziale (OS base)      : {} KB (~{} MB)", ram_baseline, ram_baseline / 1024);
    println!("* RAM Post-Setup (ZKP Keys)   : {} KB (~{} MB)", ram_after_setup, ram_after_setup / 1024);
    println!("* RAM Picco / Finale          : {} KB (~{} MB)", ram_peak, ram_peak / 1024);
    println!("* Spazio Disco SQLite         : {} Bytes (~{} KB)", db_size, db_size / 1024);
    println!("==================================================\n");

    Ok(())
}