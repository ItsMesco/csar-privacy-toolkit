#[path = "../local_privacy_ledger.rs"]
mod local_privacy_ledger;

use local_privacy_ledger::LocalPrivacyLedger;
use std::env;
use std::path::Path;

fn main() {
    println!("==================================================");
    println!("  CSAR Privacy Ledger - Strumento di Audit Forense");
    println!("==================================================\\n");

    // 1. Prendi il percorso del DB dagli argomenti (o usa quello di default)
    let args: Vec<String> = env::args().collect();
    let db_path = if args.len() > 1 { &args[1] } else { "demo_ledger.db" };

    if !Path::new(db_path).exists() {
        println!("❌ Errore: File database '{}' non trovato.", db_path);
        return;
    }

    println!("🔍 Analisi del file: {}", db_path);

    // 2. Apri il ledger
    let ledger = LocalPrivacyLedger::open(db_path).expect("Impossibile aprire il DB");

    // 3. Statistiche Base
    let count = ledger.event_count().unwrap_or(0);
    println!("📊 Eventi registrati nel ledger : {}", count);

    // 4. Estrazione Checkpoint
    if let Ok(Some(stored_root)) = ledger.get_latest_checkpoint() {
        println!("🔐 Ultimo Checkpoint salvato    : {}", hex::encode(stored_root));
    } else {
        println!("⚠️ Nessun checkpoint trovato nella tabella ledger_checkpoints.");
    }

    // 5. Ricalcolo dell'Albero di Merkle dal vivo
    if let Ok(Some(calculated_root)) = ledger.merkle_root() {
        println!("🧮 Radice ricalcolata dalle foglie: {}", hex::encode(calculated_root));
    } else {
        println!("⚠️ Impossibile calcolare la radice (ledger vuoto?).");
    }

    // 6. Verifica Integrità (La funzione che hai già scritto)
    println!("\\n--------------------------------------------------");
    match ledger.verify_integrity() {
        Ok(true) => println!("✅ RISULTATO: Integrità verificata. Nessuna manomissione rilevata."),
        Ok(false) => println!("❌ RISULTATO: MANOMISSIONE RILEVATA! L'albero di Merkle è corrotto."),
        Err(e) => println!("❌ ERRORE CRITICO durante l'audit: {}", e),
    }
    println!("==================================================\\n");
}