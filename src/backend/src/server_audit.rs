use chrono::{DateTime, Utc};
use rs_merkle::{Hasher, MerkleTree, algorithms::Sha256 as MerkleSha256};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha2_256};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditEventType {
    DatabasePublished,
    DatabaseDownloaded,
    LocalMatchDetected,
    ProofReceived,
    ProofVerified,
    ProofRejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: i64,
    pub event_type: AuditEventType,
    pub timestamp: DateTime<Utc>,
    pub database_version: String,
    pub payload: String,
}

impl AuditEvent {
    pub fn new(
        event_type: AuditEventType,
        database_version: impl Into<String>,
        payload: impl Into<String>,
    ) -> Self {
        Self {
            id: 0,
            event_type,
            timestamp: Utc::now(),
            database_version: database_version.into(),
            payload: payload.into(),
        }
    }
}

pub struct PrivacyLedger {
    conn: Connection,
}

impl PrivacyLedger {
    pub fn open(db_path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS audit_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type       TEXT NOT NULL,
                timestamp        TEXT NOT NULL,
                database_version TEXT NOT NULL,
                payload          TEXT NOT NULL
            );
            ",
        )?;

        Ok(Self { conn })
    }

    pub fn append_event(&self, event: &AuditEvent) -> rusqlite::Result<i64> {
        self.conn.execute(
            "
            INSERT INTO audit_events (
                event_type,
                timestamp,
                database_version,
                payload
            )
            VALUES (?1, ?2, ?3, ?4)
            ",
            params![
                format!("{:?}", event.event_type),
                event.timestamp.to_rfc3339(),
                event.database_version,
                event.payload,
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn event_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
    }

    pub fn event_leaves(&self) -> rusqlite::Result<Vec<[u8; 32]>> {
        let mut statement = self.conn.prepare(
            "
            SELECT id, event_type, timestamp, database_version, payload
            FROM audit_events
            ORDER BY id ASC
            ",
        )?;

        let rows = statement.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let event_type: String = row.get(1)?;
            let timestamp: String = row.get(2)?;
            let database_version: String = row.get(3)?;
            let payload: String = row.get(4)?;

            let canonical_event = format!(
                "{}|{}|{}|{}|{}",
                id, event_type, timestamp, database_version, payload
            );

            let digest = Sha2_256::digest(canonical_event.as_bytes());
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&digest);

            Ok(leaf)
        })?;

        rows.collect()
    }

    pub fn merkle_root(&self) -> rusqlite::Result<Option<[u8; 32]>> {
        let leaves = self.event_leaves()?;

        if leaves.is_empty() {
            return Ok(None);
        }

        let tree = MerkleTree::<MerkleSha256>::from_leaves(&leaves);
        Ok(tree.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_a_proof_verified_event() {
        let event = AuditEvent::new(
            AuditEventType::ProofVerified,
            "test-db-v1",
            r#"{"proof_valid":true}"#,
        );

        assert_eq!(event.id, 0);
        assert_eq!(event.event_type, AuditEventType::ProofVerified);
        assert_eq!(event.database_version, "test-db-v1");
        assert_eq!(event.payload, r#"{"proof_valid":true}"#);
    }
    #[test]
    fn appends_event_to_sqlite_ledger() {
        let ledger = PrivacyLedger::open(":memory:").unwrap();

        let event = AuditEvent::new(
            AuditEventType::ProofVerified,
            "test-db-v1",
            r#"{"proof_valid":true}"#,
        );

        let id = ledger.append_event(&event).unwrap();

        assert_eq!(id, 1);
        assert_eq!(ledger.event_count().unwrap(), 1);
    }
    #[test]
    fn merkle_root_changes_when_a_new_event_is_added() {
        let ledger = PrivacyLedger::open(":memory:").unwrap();

        let first_event = AuditEvent::new(
            AuditEventType::DatabasePublished,
            "test-db-v1",
            r#"{"entries":1}"#,
        );

        ledger.append_event(&first_event).unwrap();
        let first_root = ledger.merkle_root().unwrap().unwrap();

        let second_event = AuditEvent::new(
            AuditEventType::ProofVerified,
            "test-db-v1",
            r#"{"proof_valid":true}"#,
        );

        ledger.append_event(&second_event).unwrap();
        let second_root = ledger.merkle_root().unwrap().unwrap();

        assert_ne!(first_root, second_root);
    }
}
