mod local_privacy_ledger;
mod scanner;

use local_privacy_ledger::SourceCategory;
use scanner::PrivacyScanner;
use hash_engine::PdqHash;
use std::path::PathBuf;

fn main() {
    println!("=== CSAR Privacy Toolkit - Demo Scanner ===\n");

    let ledger_path = "demo_ledger.db";
    let mut scanner = PrivacyScanner::new(
        ledger_path,
        "csar-db-v1.0",
        "demo-merkle-root",
    ).expect("Failed to open ledger");

    match scanner.verify_integrity() {
        Ok(true) => println!("✓ Ledger integrity check passed\n"),
        Ok(false) => println!("⚠ WARNING: Ledger integrity check failed!\n"),
        Err(e) => println!("✗ Integrity check error: {}\n", e),
    }

    let reference_hash = PdqHash([0x00; 32]);

    let test_images = vec![
        "../hash-engine/tests/images/test.jpg",
        "../hash-engine/tests/images/testvar.jpg",
    ];

    println!("Scanning {} images...\n", test_images.len());

    for (i, path_str) in test_images.iter().enumerate() {
        let path = PathBuf::from(path_str);

        if !path.exists() {
            println!("⚠ Image not found: {}", path_str);
            continue;
        }

        match scanner.scan_image(&path, &reference_hash, SourceCategory::TestFixture) {
            Ok(outcome) => {
                println!("{}. {} -> {:?}", i + 1, path_str, outcome);
            }
            Err(e) => {
                println!("✗ Error scanning {}: {}", path_str, e);
            }
        }
    }

    if let Some(root) = scanner.ledger().merkle_root().unwrap_or(None) {
        scanner.ledger().save_checkpoint(root).unwrap();
        println!("Checkpoint saved\n");
    }
    
    println!("\n=== Ledger Stats ===");
    println!("Total events: {}", scanner.ledger().event_count().unwrap_or(0));

    if let Some(root) = scanner.ledger().merkle_root().unwrap_or(None) {
        println!("Merkle root: {}", hex::encode(&root[..8]));
    }

    if let Some(checkpoint) = scanner.ledger().get_latest_checkpoint().unwrap_or(None) {
        println!("Latest checkpoint: {}", hex::encode(&checkpoint[..8]));
    }

    println!("\nLedger saved to: {}", ledger_path);
    println!("Inspect with: sqlite3 {} 'SELECT id, scan_outcome, content_commitment FROM client_audit_events;'", ledger_path);
}