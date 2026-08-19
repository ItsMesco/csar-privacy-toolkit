use chrono::{DateTime, Utc};
use ledger_core::{hash_event, merkle_root, LedgerEvent};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fmt::Write;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceCategory {
    Outgoing,
    Incoming,
    Unknown,
    TestFixture,
}

impl SourceCategory {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Incoming => "incoming",
            Self::Unknown => "unknown",
            Self::TestFixture => "test_fixture",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanOutcome {
    NoMatch,
    Match,
    CandidateMatch,
}

impl ScanOutcome {
    fn as_str(&self) -> &'static str {
        match self {
            Self::NoMatch => "no_match",
            Self::Match => "match",
            Self::CandidateMatch => "candidate_match",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAuditEvent {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub database_version: String,
    pub database_root: String,
    pub source_category: SourceCategory,
    pub outcome: ScanOutcome,
    pub content_commitment: String,
    pub schema_version: u32,
}

impl ClientAuditEvent {
    pub fn new(
        database_version: impl Into<String>,
        database_root: impl Into<String>,
        source_category: SourceCategory,
        outcome: ScanOutcome,
        content_commitment: impl Into<String>,
    ) -> Self {
        Self {
            id: 0,
            timestamp: Utc::now(),
            database_version: database_version.into(),
            database_root: database_root.into(),
            source_category,
            outcome,
            content_commitment: content_commitment.into(),
            schema_version: 1,
        }
    }
}

impl LedgerEvent for ClientAuditEvent {


    fn canonical_representation(&self) -> String {
        let mut representation = String::new();

        let _ = write!(
            &mut representation,
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.id,
            self.timestamp.to_rfc3339(),
            self.database_version,
            self.database_root,
            self.source_category.as_str(),
            self.outcome.as_str(),
            self.content_commitment,
            self.schema_version,
        );

        representation
    }
}

pub struct LocalPrivacyLedger {
    conn: Connection,
}

impl LocalPrivacyLedger {
    pub fn open(database_path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(database_path)?;

        conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS client_audit_events (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp          TEXT NOT NULL,
                database_version   TEXT NOT NULL,
                database_root      TEXT NOT NULL,
                scan_source        TEXT NOT NULL,
                scan_outcome       TEXT NOT NULL,
                content_commitment TEXT NOT NULL,
                schema_version     INTEGER NOT NULL,
                leaf_hash          BLOB NOT NULL
            );
            ",
        )?;

        Ok(Self { conn })
    }

    pub fn append_event(&self, event: &ClientAuditEvent) -> rusqlite::Result<i64> {
        self.conn.execute(
            "
            INSERT INTO client_audit_events (
                timestamp,
                database_version,
                database_root,
                scan_source,
                scan_outcome,
                content_commitment,
                schema_version,
                leaf_hash
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, zeroblob(32))
            ",
            params![
                event.timestamp.to_rfc3339(),
                event.database_version,
                event.database_root,
                event.source_category.as_str(),
                event.outcome.as_str(),
                event.content_commitment,
                event.schema_version,
            ],
        )?;

        let id = self.conn.last_insert_rowid();

        let persisted_event = ClientAuditEvent {
            id,
            timestamp: event.timestamp,
            database_version: event.database_version.clone(),
            database_root: event.database_root.clone(),
            source_category: event.source_category.clone(),
            outcome: event.outcome.clone(),
            content_commitment: event.content_commitment.clone(),
            schema_version: event.schema_version,
        };

        let leaf = hash_event(&persisted_event);

        self.conn.execute(
            "UPDATE client_audit_events SET leaf_hash = ?1 WHERE id = ?2",
            params![leaf.to_vec(), id],
        )?;

        Ok(id)
    }

    pub fn event_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM client_audit_events", [], |row| {
                row.get::<_, i64>(0)
            })
    }

    pub fn event_leaves(&self) -> rusqlite::Result<Vec<[u8; 32]>> {
        let mut statement = self.conn.prepare(
            "
            SELECT leaf_hash
            FROM client_audit_events
            ORDER BY id ASC
            ",
        )?;

        let rows = statement.query_map([], |row| {
            let leaf_blob: Vec<u8> = row.get(0)?;

            let leaf: [u8; 32] = leaf_blob.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "leaf_hash non ha lunghezza 32 byte",
                    )),
                )
            })?;

            Ok(leaf)
        })?;

        rows.collect()
    }

    pub fn merkle_root(&self) -> rusqlite::Result<Option<[u8; 32]>> {
        let leaves = self.event_leaves()?;
        Ok(merkle_root(&leaves))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_core::hash_event;

    #[test]
    fn client_event_has_stable_canonical_representation() {
        let event = ClientAuditEvent {
            id: 7,
            timestamp: "2026-08-18T10:45:00Z".parse().unwrap(),
            database_version: "test-db-v1".to_string(),
            database_root: "db-root-123".to_string(),
            source_category: SourceCategory::Incoming,
            outcome: ScanOutcome::NoMatch,
            content_commitment: "commitment-abc".to_string(),
            schema_version: 1,
        };

        assert_eq!(
            event.canonical_representation(),
            "7|2026-08-18T10:45:00+00:00|test-db-v1|db-root-123|incoming|no_match|commitment-abc|1"
        );
    }

    #[test]
    fn changing_scan_outcome_changes_leaf_hash() {
        let mut event = ClientAuditEvent {
            id: 1,
            timestamp: "2026-08-18T10:45:00Z".parse().unwrap(),
            database_version: "test-db-v1".to_string(),
            database_root: "db-root-123".to_string(),
            source_category: SourceCategory::Incoming,
            outcome: ScanOutcome::NoMatch,
            content_commitment: "commitment-abc".to_string(),
            schema_version: 1,
        };

        let no_match_leaf = hash_event(&event);

        event.outcome = ScanOutcome::Match;

        let match_leaf = hash_event(&event);

        assert_ne!(no_match_leaf, match_leaf);
    }

    #[test]
    fn appends_event_to_local_sqlite_ledger() {
        let ledger = LocalPrivacyLedger::open(":memory:").unwrap();

        let event = ClientAuditEvent::new(
            "test-db-v1",
            "db-root-123",
            SourceCategory::TestFixture,
            ScanOutcome::NoMatch,
            "commitment-abc",
        );

        let id = ledger.append_event(&event).unwrap();

        assert_eq!(id, 1);
        assert_eq!(ledger.event_count().unwrap(), 1);
    }

    #[test]
    fn merkle_root_changes_after_appending_event() {
        let ledger = LocalPrivacyLedger::open(":memory:").unwrap();

        let first_event = ClientAuditEvent::new(
            "test-db-v1",
            "db-root-123",
            SourceCategory::TestFixture,
            ScanOutcome::NoMatch,
            "commitment-first",
        );

        ledger.append_event(&first_event).unwrap();
        let first_root = ledger.merkle_root().unwrap().unwrap();

        let second_event = ClientAuditEvent::new(
            "test-db-v1",
            "db-root-123",
            SourceCategory::TestFixture,
            ScanOutcome::Match,
            "commitment-second",
        );

        ledger.append_event(&second_event).unwrap();
        let second_root = ledger.merkle_root().unwrap().unwrap();

        assert_ne!(first_root, second_root);
    }
}