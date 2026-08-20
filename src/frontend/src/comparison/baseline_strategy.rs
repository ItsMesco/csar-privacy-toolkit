use super::{ComparisonContext, ComparisonError, ComparisonResult, ComparisonStrategy};
use crate::local_privacy_ledger::ScanOutcome;
use hash_engine::{is_match, PdqHash};

/// Serve come riferimento di performance prima di introdurre crittografia.
pub struct BaselineStrategy;

impl ComparisonStrategy for BaselineStrategy {
    fn name(&self) -> &'static str {
        "baseline"
    }

    fn compare(
        &self,
        local_hash: &PdqHash,
        context: &ComparisonContext,
    ) -> Result<ComparisonResult, ComparisonError> {
        let outcome = if is_match(local_hash, &context.reference_hash, context.threshold) {
            ScanOutcome::Match
        } else {
            ScanOutcome::NoMatch
        };

        Ok(ComparisonResult {
            outcome,
            proof: None,
        })
    }
}
