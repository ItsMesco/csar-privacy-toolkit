pub mod baseline_strategy;
pub mod zkp_strategy;
pub mod zkp_membership_strategy;
mod zkp_circuit;
pub(crate) mod zkp_engine;
pub(crate) mod zkp_membership_engine;
mod zkp_membership_circuit;
mod phe_engine;
mod phe_strategy;

use crate::local_privacy_ledger::ScanOutcome;
use hash_engine::PdqHash;

#[derive(Debug, Clone)]
pub struct ComparisonContext {
    pub reference_hash: PdqHash,
    pub threshold: u32,
    // Dati necessari solo alla strategia con membership proof.
    // Baseline e ZKP diretta li ignorano.
    pub db_root: [u8; 32],
    pub merkle_path: Vec<([u8; 32], bool)>,
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
impl From<ComparisonError> for rusqlite::Error {
    fn from(err: ComparisonError) -> Self {
        rusqlite::Error::ToSqlConversionFailure(Box::new(err))
    }
}
pub trait ComparisonStrategy {
    fn name(&self) -> &'static str;

    fn compare(
        &self,
        local_hash: &PdqHash,
        context: &ComparisonContext,
    ) -> Result<ComparisonResult, ComparisonError>;

    /// Verifica "lato server" della proof prodotta da compare().
    /// Default: la strategia non produce proof.
    fn verify(&self, proof: &[u8], context: &ComparisonContext) -> Result<bool, ComparisonError> {
        let _ = (proof, context);
        Err(ComparisonError::Internal(format!(
            "La strategia '{}' non produce proof verificabili",
            self.name()
        )))
    }

    /// Verifying key serializzata, per il test E2E via backend.
    fn verifying_key_bytes(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Il registry: main.rs non conosce le strategie, le chiede qui.
pub fn available_strategies() -> &'static [&'static str] {
    &["baseline", "zkp", "zkp-membership", "phe"]
}

pub fn build_strategy(
    mode: &str,
    db_len: usize,
) -> Result<Box<dyn ComparisonStrategy>, ComparisonError> {
    let depth = (db_len as u32).ilog2() as usize;
    match mode {
        "baseline" => Ok(Box::new(baseline_strategy::BaselineStrategy)),
        "zkp" => Ok(Box::new(zkp_strategy::ZkpStrategy::new()?)),
        "zkp-membership" => Ok(Box::new(zkp_membership_strategy::ZkpMembershipStrategy::new(depth)?)),
        "phe" => Ok(Box::new(phe_strategy::PheStrategy::new(2048))),
        other => Err(ComparisonError::Internal(format!("Modalità sconosciuta: '{}'", other))),
    }
}

