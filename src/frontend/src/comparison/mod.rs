pub mod baseline_strategy;
mod zkp_circuit;
pub(crate) mod zkp_engine;

use crate::local_privacy_ledger::ScanOutcome;
use hash_engine::PdqHash;

#[derive(Debug, Clone)]
pub struct ComparisonContext {
    pub reference_hash: PdqHash,
    pub threshold: u32,
}

#[derive(Debug)]
pub struct ComparisonResult {
    pub outcome: ScanOutcome,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum ComparisonError {
    Internal(String),
}

impl std::fmt::Display for ComparisonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonError::Internal(msg) => write!(f, "Comparison error: {}", msg),
        }
    }
}

impl std::error::Error for ComparisonError {}

pub trait ComparisonStrategy {
    fn name(&self) -> &'static str;

    fn compare(
        &self,
        local_hash: &PdqHash,
        context: &ComparisonContext,
    ) -> Result<ComparisonResult, ComparisonError>;
}

pub fn build_strategy(mode: &str) -> Box<dyn ComparisonStrategy> {
    match mode {
        "baseline" => Box::new(baseline_strategy::BaselineStrategy),
        other => panic!(
            "Modalità sconosciuta: '{}'. Usa 'baseline' (phe/zkp arriveranno dopo).",
            other
        ),
    }
}
