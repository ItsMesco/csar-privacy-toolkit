mod comparison;
mod local_privacy_ledger;
mod metrics;
mod scanner;

use comparison::build_strategy;
use hash_engine::{PdqHash, DEF_MATCH_THRESHOLD};
use local_privacy_ledger::SourceCategory;
use scanner::PrivacyScanner;
use std::path::PathBuf;

fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "baseline".to_string());

    println!(
        "=== CSAR Privacy Toolkit - Demo Scanner (mode: {}) ===\n",
        mode
    );

    let strategy = build_strategy(&mode);
    let ledger_path = "demo_ledger.db";

    let mut scanner =
        PrivacyScanner::new(ledger_path, "csar-db-v1.0", "demo-merkle-root", strategy)
            .expect("Failed to open ledger");

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

        match scanner.scan_image(
            &path,
            &reference_hash,
            DEF_MATCH_THRESHOLD,
            SourceCategory::TestFixture,
        ) {
            Ok(outcome) => println!("{}. {} -> {:?}", i + 1, path_str, outcome),
            Err(e) => println!("✗ Error scanning {}: {}", path_str, e),
        }
    }

    println!("\n=== Ledger Stats ===");
    println!(
        "Total events: {}",
        scanner.ledger().event_count().unwrap_or(0)
    );

    if let Some(root) = scanner.ledger().merkle_root().unwrap_or(None) {
        println!("Merkle root: {}", hex::encode(&root[..8]));
    }

    println!("\n{}", scanner.metrics().report());
}
