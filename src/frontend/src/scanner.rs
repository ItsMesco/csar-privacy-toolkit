use crate::comparison::{ComparisonContext, ComparisonStrategy};
use crate::local_privacy_ledger::SourceCategory;
use crate::local_privacy_ledger::{ClientAuditEvent, LocalPrivacyLedger, ScanOutcome};
use crate::metrics::{measure, MetricsCollector};
use hash_engine::{compute_pdq_from_path, PdqHash};
use std::path::Path;

pub struct PrivacyScanner {
    ledger: LocalPrivacyLedger,
    strategy: Box<dyn ComparisonStrategy>,
    metrics: MetricsCollector,
    database_version: String,
    database_root: String,
    checkpoint_interval: u64,
    scans_since_checkpoint: u64,
}

impl PrivacyScanner {
    pub fn new(
        ledger_path: &str,
        database_version: &str,
        database_root: &str,
        strategy: Box<dyn ComparisonStrategy>,
    ) -> Result<Self, rusqlite::Error> {
        let ledger = LocalPrivacyLedger::open(ledger_path)?;
        Ok(Self {
            ledger,
            strategy,
            metrics: MetricsCollector::new(),
            database_version: database_version.to_string(),
            database_root: database_root.to_string(),
            checkpoint_interval: 10,
            scans_since_checkpoint: 0,
        })
    }

    pub fn scan_image<P: AsRef<Path>>(
        &mut self,
        path: P,
        reference_hash: &PdqHash,
        threshold: u32,
        source: SourceCategory,
    ) -> Result<ScanOutcome, Box<dyn std::error::Error>> {
        let image_hash = compute_pdq_from_path(path)?;

        let ctx = ComparisonContext {
            reference_hash: *reference_hash,
            threshold,
        };

        let strategy_name = self.strategy.name();
        let strategy = &self.strategy;

        let (metrics, comparison_result) =
            measure(strategy_name, || strategy.compare(&image_hash, &ctx));

        self.metrics.record(metrics);

        let outcome = comparison_result.outcome;

        let event = ClientAuditEvent::new(
            &self.database_version,
            &self.database_root,
            source,
            outcome.clone(),
            &image_hash.to_hex(),
        );

        self.ledger.append_event(&event)?;
        self.scans_since_checkpoint += 1;

        if self.scans_since_checkpoint >= self.checkpoint_interval {
            if let Some(root) = self.ledger.merkle_root()? {
                self.ledger.save_checkpoint(root)?;
            }
            self.scans_since_checkpoint = 0;
        }

        Ok(outcome)
    }

    pub fn verify_integrity(&self) -> Result<bool, rusqlite::Error> {
        self.ledger.verify_integrity()
    }

    pub fn ledger(&self) -> &LocalPrivacyLedger {
        &self.ledger
    }

    pub fn metrics(&self) -> &MetricsCollector {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comparison::build_strategy;
    use hash_engine::DEF_MATCH_THRESHOLD;
    use std::fs;

    #[test]
    fn scanner_appends_event_and_checkpoints() {
        let temp_dir = std::env::temp_dir();
        let ledger_path = temp_dir.join("test_scanner_ledger.db");
        let _ = fs::remove_file(&ledger_path);

        let strategy = build_strategy("baseline");
        let mut scanner = PrivacyScanner::new(
            ledger_path.to_str().unwrap(),
            "test-db-v1",
            "db-root-123",
            strategy,
        )
        .unwrap();

        let reference = PdqHash([0x00; 32]);
        let test_image = "../hash-engine/tests/images/test.jpg";

        let _outcome = scanner
            .scan_image(
                test_image,
                &reference,
                DEF_MATCH_THRESHOLD,
                SourceCategory::TestFixture,
            )
            .unwrap();

        assert_eq!(scanner.ledger().event_count().unwrap(), 1);
        assert_eq!(scanner.metrics().len(), 1);

        for _ in 0..9 {
            scanner
                .scan_image(
                    test_image,
                    &reference,
                    DEF_MATCH_THRESHOLD,
                    SourceCategory::TestFixture,
                )
                .unwrap();
        }

        assert!(scanner.ledger().get_latest_checkpoint().unwrap().is_some());
        assert_eq!(scanner.metrics().len(), 10);
    }
}
