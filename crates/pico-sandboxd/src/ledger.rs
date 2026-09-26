//! Durable SQLite ledger for host-local `sandboxd` state.
//!
//! The ledger stores only restart-relevant observations: accepted fencing and
//! policy epochs, operation intents and outcomes, resource receipts, process
//! identity, and reconciliation findings. It intentionally excludes user data,
//! credentials, and stream payloads.

use std::path::Path;

use pico_core::{
    BackendMetadata, FencingToken, NonReadyReason, OperationId, ResourceReceipt, RuntimeType,
    SandboxId, SandboxState,
};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::{Row, SqlitePool};

use crate::supervisor::{
    OperationKind, OperationOutcome, OutcomeReason, OutcomeStatus, ResourceReceiptStatus,
    SandboxStatus, SupervisorError,
};

/// A row returned by the GC scan query for one outstanding resource receipt.
#[derive(Debug, Clone)]
pub(crate) struct GcScanRow {
    /// Sandbox that owns the resource.
    pub sandbox_id: String,
    /// Resource class (e.g., "workspace", "cgroup").
    pub resource_class: String,
    /// Deterministic resource name.
    pub resource_name: String,
    /// Current cleanup state: "present" or "released".
    #[expect(dead_code, reason = "reserved for future GC scan filtering by state")]
    pub cleanup_state: String,
    /// Observed sandbox lifecycle state from the sandboxes table.
    pub observed_state: String,
    /// Receipt payload such as the serialized CPU allocation record.
    pub external_id: Option<String>,
}

/// A row returned when rebuilding CPU allocations from durable receipts.
#[derive(Debug, Clone)]
pub(crate) struct CpuReceiptRow {
    /// Sandbox that owns the CPU allocation.
    pub sandbox_id: String,
    /// Serialized allocation record (tenant and CPU set) stored on the receipt.
    pub external_id: Option<String>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sandboxes (
    sandbox_id TEXT PRIMARY KEY,
    fencing_epoch INTEGER NOT NULL,
    fencing_sequence INTEGER NOT NULL,
    policy_epoch INTEGER NOT NULL,
    runtime TEXT NOT NULL,
    backend_version TEXT NOT NULL,
    observed_state TEXT NOT NULL,
    host_boot_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(sandbox_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    deadline_unix_ms INTEGER NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    non_ready_reason TEXT,
    message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS operations_by_sandbox
    ON operations(sandbox_id, updated_at);

CREATE TABLE IF NOT EXISTS resource_receipts (
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(sandbox_id) ON DELETE CASCADE,
    operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE CASCADE,
    class TEXT NOT NULL,
    name TEXT NOT NULL,
    external_id TEXT,
    cleanup_state TEXT NOT NULL DEFAULT 'present',
    PRIMARY KEY (sandbox_id, class, name)
);

CREATE TABLE IF NOT EXISTS process_identities (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
    sandbox_id TEXT NOT NULL REFERENCES sandboxes(sandbox_id) ON DELETE CASCADE,
    pid INTEGER NOT NULL,
    process_start_ticks INTEGER,
    host_boot_id TEXT NOT NULL,
    executable TEXT NOT NULL,
    cgroup_identity TEXT,
    pidfd_available INTEGER NOT NULL,
    state TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reconciliation_findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_id TEXT,
    operation_id TEXT,
    classification TEXT NOT NULL,
    evidence TEXT NOT NULL,
    action TEXT NOT NULL,
    review_reason TEXT,
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL
);
"#;

#[derive(Clone)]
pub(crate) struct Ledger {
    pool: SqlitePool,
}

/// Outcome from attempting to register a new operation in the ledger.
pub(crate) enum BeginOperation {
    /// No matching operation was found, so execution should proceed.
    Execute,
    /// A terminal result already exists for the same operation identity.
    Replay(Box<OperationOutcome>),
}

/// Durable fields needed to register one new supervised operation.
pub(crate) struct BeginOperationRequest<'a> {
    pub context: &'a crate::supervisor::CommandContext,
    pub kind: OperationKind,
    pub metadata: &'a BackendMetadata,
    pub state: SandboxState,
    pub host_boot_id: &'a str,
}

pub(crate) struct ProcessIdentityRecord<'a> {
    pub operation_id: &'a OperationId,
    pub sandbox_id: &'a SandboxId,
    pub pid: u32,
    pub process_start_ticks: Option<u64>,
    pub host_boot_id: &'a str,
    pub executable: &'a str,
    pub cgroup_identity: Option<&'a str>,
    pub pidfd_available: bool,
}

impl Ledger {
    /// Opens the durable SQLite ledger at the supplied path.
    pub(crate) fn open(path: &Path) -> Result<Self, SupervisorError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true);
        Ok(Self {
            pool: SqlitePoolOptions::new()
                .max_connections(1)
                .connect_lazy_with(options),
        })
    }

    /// Creates an in-memory SQLite ledger for tests.
    pub(crate) fn in_memory() -> Self {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .journal_mode(SqliteJournalMode::Memory)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true);
        Self {
            pool: SqlitePoolOptions::new()
                .max_connections(1)
                .connect_lazy_with(options),
        }
    }

    /// Ensures the schema exists before the first operation uses the ledger.
    pub(crate) async fn initialize(&self) -> Result<(), SupervisorError> {
        sqlx::raw_sql(SCHEMA).execute(&self.pool).await?;
        self.ensure_non_ready_reason_column().await?;
        Ok(())
    }

    async fn ensure_non_ready_reason_column(&self) -> Result<(), SupervisorError> {
        let columns = sqlx::query("PRAGMA table_info(operations)")
            .fetch_all(&self.pool)
            .await?;
        let exists = columns
            .iter()
            .any(|row| row.get::<String, _>("name") == "non_ready_reason");
        if !exists {
            sqlx::query("ALTER TABLE operations ADD COLUMN non_ready_reason TEXT")
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Registers an operation intent or returns a durable replay result.
    ///
    /// This method enforces fencing monotonicity, policy monotonicity, and
    /// operation identity uniqueness before any side effect is allowed to run.
    pub(crate) async fn begin_operation(
        &self,
        request: BeginOperationRequest<'_>,
    ) -> Result<BeginOperation, SupervisorError> {
        let mut transaction = self.pool.begin().await?;
        let operation_id = request.context.operation_id.as_str();
        if let Some(row) = sqlx::query(
            "SELECT operation_id, sandbox_id, kind, status, reason, non_ready_reason, message, updated_at
             FROM operations WHERE operation_id = ?",
        )
        .bind(operation_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let outcome = operation_outcome_from_row(&row)?;
            if outcome.sandbox_id != request.context.sandbox_id || outcome.kind != request.kind {
                return Err(SupervisorError::OperationIdentityConflict(
                    operation_id.to_string(),
                ));
            }
            if outcome.status.is_terminal() {
                transaction.commit().await?;
                return Ok(BeginOperation::Replay(Box::new(outcome)));
            }
            return Err(SupervisorError::OperationInProgress(
                operation_id.to_string(),
            ));
        }

        let sandbox_id = request.context.sandbox_id.as_str();
        let current = sqlx::query(
            "SELECT fencing_epoch, fencing_sequence, policy_epoch FROM sandboxes WHERE sandbox_id = ?",
        )
        .bind(sandbox_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(row) = current {
            let current_token = FencingToken {
                epoch: to_u64(row.try_get::<i64, _>("fencing_epoch")?, "fencing epoch")?,
                sequence: to_u64(
                    row.try_get::<i64, _>("fencing_sequence")?,
                    "fencing sequence",
                )?,
            };
            if request
                .context
                .assignment_fencing_token
                .is_stale(&current_token)
            {
                return Err(SupervisorError::StaleFencingToken {
                    request: request.context.assignment_fencing_token,
                    current: current_token,
                });
            }
            let current_epoch = to_u64(row.try_get::<i64, _>("policy_epoch")?, "policy epoch")?;
            if request.context.policy_epoch < current_epoch {
                return Err(SupervisorError::StalePolicyEpoch {
                    request: request.context.policy_epoch,
                    current: current_epoch,
                });
            }
        }

        let now = pico_core::now_iso();
        sqlx::query(
            "INSERT INTO sandboxes (
                sandbox_id, fencing_epoch, fencing_sequence, policy_epoch, runtime,
                backend_version, observed_state, host_boot_id, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(sandbox_id) DO UPDATE SET
                fencing_epoch = excluded.fencing_epoch,
                fencing_sequence = excluded.fencing_sequence,
                policy_epoch = MAX(sandboxes.policy_epoch, excluded.policy_epoch),
                runtime = excluded.runtime,
                backend_version = excluded.backend_version,
                observed_state = excluded.observed_state,
                host_boot_id = excluded.host_boot_id,
                updated_at = excluded.updated_at",
        )
        .bind(sandbox_id)
        .bind(to_i64(
            request.context.assignment_fencing_token.epoch,
            "fencing epoch",
        )?)
        .bind(to_i64(
            request.context.assignment_fencing_token.sequence,
            "fencing sequence",
        )?)
        .bind(to_i64(request.context.policy_epoch, "policy epoch")?)
        .bind(runtime_to_str(request.metadata.runtime))
        .bind(&request.metadata.version)
        .bind(state_to_str(request.state))
        .bind(request.host_boot_id)
        .bind(&now)
        .bind(&now)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO operations (
                operation_id, sandbox_id, kind, deadline_unix_ms, status,
                created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(operation_id)
        .bind(sandbox_id)
        .bind(kind_to_str(request.kind))
        .bind(request.context.deadline_unix_ms)
        .bind(status_to_str(OutcomeStatus::Running))
        .bind(&now)
        .bind(&now)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(BeginOperation::Execute)
    }

    /// Persists a terminal outcome and any newly proven resource receipts.
    pub(crate) async fn complete_operation(
        &self,
        outcome: &OperationOutcome,
        state: SandboxState,
        resources: &[ResourceReceipt],
    ) -> Result<(), SupervisorError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "UPDATE operations
             SET status = ?, reason = ?, non_ready_reason = ?, message = ?, updated_at = ?
             WHERE operation_id = ?",
        )
        .bind(status_to_str(outcome.status))
        .bind(reason_to_str(outcome.reason))
        .bind(outcome.non_ready_reason.map(non_ready_reason_to_str))
        .bind(outcome.message.as_deref())
        .bind(&outcome.completed_at)
        .bind(outcome.operation_id.as_str())
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE sandboxes SET observed_state = ?, updated_at = ? WHERE sandbox_id = ?")
            .bind(state_to_str(state))
            .bind(&outcome.completed_at)
            .bind(outcome.sandbox_id.as_str())
            .execute(&mut *transaction)
            .await?;
        if !resources.is_empty() {
            let mut builder = sqlx::QueryBuilder::new(
                "INSERT INTO resource_receipts (sandbox_id, operation_id, class, name, external_id, cleanup_state) ",
            );
            builder.push_values(resources, |mut b, resource| {
                b.push_bind(outcome.sandbox_id.as_str())
                    .push_bind(outcome.operation_id.as_str())
                    .push_bind(&resource.class)
                    .push_bind(&resource.name)
                    .push_bind(resource.external_id.as_deref())
                    .push_bind("present");
            });
            builder.push(
                " ON CONFLICT(sandbox_id, class, name) DO UPDATE SET operation_id = excluded.operation_id, external_id = excluded.external_id, cleanup_state = 'present'",
            );
            builder.build().execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Marks resource receipts as released after successful cleanup.
    pub(crate) async fn mark_resources_released(
        &self,
        sandbox_id: &SandboxId,
        released: &[String],
    ) -> Result<(), SupervisorError> {
        let mut transaction = self.pool.begin().await?;
        for name in released {
            sqlx::query(
                "UPDATE resource_receipts SET cleanup_state = 'released'
                 WHERE sandbox_id = ? AND name = ?",
            )
            .bind(sandbox_id.as_str())
            .bind(name)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Returns the kind of the most recently updated operation recorded for
    /// one sandbox, if any.
    ///
    /// Operations are serialized per sandbox, so the latest row is
    /// unambiguous. A `Failed` sandbox whose latest operation is destroy
    /// still carries destroy intent: the destroy ran into partial cleanup
    /// (or a restart) after tear-down already began, while a sandbox failed
    /// at any earlier lifecycle step never reached it.
    pub(crate) async fn latest_operation_kind(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<Option<OperationKind>, SupervisorError> {
        let kind = sqlx::query_scalar::<_, String>(
            "SELECT kind FROM operations WHERE sandbox_id = ? ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(sandbox_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        kind.map(|kind| kind_from_str(&kind)).transpose()
    }

    /// Reads one persisted host-local sandbox observation.
    pub(crate) async fn sandbox_status(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<Option<SandboxStatus>, SupervisorError> {
        let row = sqlx::query(
            "SELECT sandbox_id, fencing_epoch, fencing_sequence, policy_epoch, runtime,
                    backend_version, observed_state, host_boot_id, updated_at
             FROM sandboxes WHERE sandbox_id = ?",
        )
        .bind(sandbox_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| sandbox_status_from_row(&row)).transpose()
    }

    /// Lists all persisted sandbox observations in deterministic order.
    pub(crate) async fn list_sandbox_statuses(
        &self,
    ) -> Result<Vec<SandboxStatus>, SupervisorError> {
        let rows = sqlx::query(
            "SELECT sandbox_id, fencing_epoch, fencing_sequence, policy_epoch, runtime,
                    backend_version, observed_state, host_boot_id, updated_at
             FROM sandboxes ORDER BY sandbox_id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(sandbox_status_from_row).collect()
    }

    /// Records durable identity evidence for one spawned host process.
    pub(crate) async fn record_process(
        &self,
        record: ProcessIdentityRecord<'_>,
    ) -> Result<(), SupervisorError> {
        let now = pico_core::now_iso();
        sqlx::query(
            "INSERT INTO process_identities (
                operation_id, sandbox_id, pid, process_start_ticks, host_boot_id,
                executable, cgroup_identity, pidfd_available, state, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?)",
        )
        .bind(record.operation_id.as_str())
        .bind(record.sandbox_id.as_str())
        .bind(i64::from(record.pid))
        .bind(
            record
                .process_start_ticks
                .map(|value| to_i64(value, "process start ticks"))
                .transpose()?,
        )
        .bind(record.host_boot_id)
        .bind(record.executable)
        .bind(record.cgroup_identity)
        .bind(record.pidfd_available)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Updates the durable lifecycle state for one supervised host process.
    pub(crate) async fn complete_process(
        &self,
        operation_id: &OperationId,
        state: &str,
    ) -> Result<(), SupervisorError> {
        sqlx::query(
            "UPDATE process_identities SET state = ?, updated_at = ? WHERE operation_id = ?",
        )
        .bind(state)
        .bind(pico_core::now_iso())
        .bind(operation_id.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Marks interrupted operations as review-required after supervisor restart.
    ///
    /// The returned count reflects every persisted review-required operation,
    /// not only the operations updated by this reconciliation pass.
    pub(crate) async fn reconcile_interrupted_operations(&self) -> Result<u64, SupervisorError> {
        let now = pico_core::now_iso();
        sqlx::query(
            "UPDATE operations
             SET status = 'requires_review', reason = 'supervisor_restarted',
                 message = 'operation was active when sandboxd restarted',
                 updated_at = ?
             WHERE status = 'running'",
        )
        .bind(&now)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE process_identities SET state = 'unrecoverable', updated_at = ?
             WHERE state = 'running'",
        )
        .bind(&now)
        .execute(&self.pool)
        .await?;
        let review_required = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM operations WHERE status = 'requires_review'",
        )
        .fetch_one(&self.pool)
        .await?;
        to_u64(review_required, "review-required operation count")
    }

    /// Lists all resource receipts recorded for one sandbox with their
    /// cleanup state, in deterministic order.
    pub(crate) async fn list_receipts(
        &self,
        sandbox_id: &SandboxId,
    ) -> Result<Vec<ResourceReceiptStatus>, SupervisorError> {
        let rows = sqlx::query(
            "SELECT class, name, cleanup_state FROM resource_receipts
             WHERE sandbox_id = ? ORDER BY class, name",
        )
        .bind(sandbox_id.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(ResourceReceiptStatus {
                    class: row.try_get::<String, _>("class")?,
                    name: row.try_get::<String, _>("name")?,
                    cleanup_state: row.try_get::<String, _>("cleanup_state")?,
                })
            })
            .collect()
    }

    /// Lists resource receipts that still need garbage collection scanning.
    ///
    /// Returns all receipts in the "present" state regardless of the sandbox
    /// lifecycle. Callers decide whether to filter on observed lifecycle state
    /// during the GC pass.
    pub(crate) async fn list_gc_scan_rows(&self) -> Result<Vec<GcScanRow>, SupervisorError> {
        let rows = sqlx::query(
            "SELECT r.sandbox_id, r.class, r.name, r.cleanup_state, r.external_id,
                    COALESCE(s.observed_state, 'absent') as observed_state
             FROM resource_receipts r
             LEFT JOIN sandboxes s ON s.sandbox_id = r.sandbox_id
             WHERE r.cleanup_state = 'present'
             ORDER BY r.sandbox_id, r.class, r.name",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(GcScanRow {
                    sandbox_id: row.try_get::<String, _>("sandbox_id")?,
                    resource_class: row.try_get::<String, _>("class")?,
                    resource_name: row.try_get::<String, _>("name")?,
                    cleanup_state: row.try_get::<String, _>("cleanup_state")?,
                    observed_state: row.try_get::<String, _>("observed_state")?,
                    external_id: row.try_get::<Option<String>, _>("external_id")?,
                })
            })
            .collect()
    }

    /// Lists present CPU allocation receipts for allocator rebuild after restart.
    ///
    /// Returns every receipt of the "cpu" class still in the "present" state
    /// whose sandbox has not reached the destroyed lifecycle state, carrying the
    /// serialized allocation record in `external_id`. These are the proven
    /// allocations a restarted daemon must restore before serving new prepares.
    ///
    /// Receipts of destroyed sandboxes are excluded: their cleanup is owned by
    /// the GC pass (which scans all present receipts regardless of lifecycle
    /// state), so restoring them would double-book cores that the GC has
    /// already decided to release. This "present and not destroyed" query is
    /// the single source of truth for the allocator rebuild; the supervisor's
    /// fencing and single-writer discipline keep it consistent against
    /// concurrent destroys during a restart.
    pub(crate) async fn list_present_cpu_receipts(
        &self,
    ) -> Result<Vec<CpuReceiptRow>, SupervisorError> {
        let rows = sqlx::query(
            "SELECT r.sandbox_id, r.external_id
             FROM resource_receipts r
             JOIN sandboxes s ON s.sandbox_id = r.sandbox_id
              AND s.observed_state != 'destroyed'
             WHERE r.class = 'cpu' AND r.cleanup_state = 'present'
             ORDER BY r.sandbox_id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(CpuReceiptRow {
                    sandbox_id: row.try_get::<String, _>("sandbox_id")?,
                    external_id: row.try_get::<Option<String>, _>("external_id")?,
                })
            })
            .collect()
    }

    /// Marks a single resource receipt as removed after successful cleanup.
    pub(crate) async fn mark_resource_removed(
        &self,
        sandbox_id: &str,
        resource_name: &str,
    ) -> Result<(), SupervisorError> {
        sqlx::query(
            "UPDATE resource_receipts SET cleanup_state = 'released'
             WHERE sandbox_id = ? AND name = ?",
        )
        .bind(sandbox_id)
        .bind(resource_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records a reconciliation finding for operator review.
    pub(crate) async fn record_finding(
        &self,
        sandbox_id: Option<&str>,
        operation_id: Option<&str>,
        classification: &str,
        evidence: &str,
        action: &str,
        review_reason: Option<&str>,
    ) -> Result<(), SupervisorError> {
        let now = pico_core::now_iso();
        sqlx::query(
            "INSERT INTO reconciliation_findings (
                sandbox_id, operation_id, classification, evidence, action,
                review_reason, first_observed_at, last_observed_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(sandbox_id)
        .bind(operation_id)
        .bind(classification)
        .bind(evidence)
        .bind(action)
        .bind(review_reason)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lists all sandbox IDs known to the durable ledger.
    pub(crate) async fn list_known_sandbox_ids(&self) -> Result<Vec<String>, SupervisorError> {
        let rows = sqlx::query("SELECT sandbox_id FROM sandboxes ORDER BY sandbox_id")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                row.try_get::<String, _>("sandbox_id")
                    .map_err(SupervisorError::from)
            })
            .collect()
    }

    /// Returns the count of reconciliation findings that require review.
    pub(crate) async fn review_required_count(&self) -> Result<u64, SupervisorError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM reconciliation_findings WHERE action = 'requires_review'",
        )
        .fetch_one(&self.pool)
        .await?;
        to_u64(count, "review-required finding count")
    }
}

fn sandbox_status_from_row(row: &SqliteRow) -> Result<SandboxStatus, SupervisorError> {
    Ok(SandboxStatus {
        sandbox_id: SandboxId::from_string(row.try_get::<String, _>("sandbox_id")?),
        assignment_fencing_token: FencingToken {
            epoch: to_u64(row.try_get::<i64, _>("fencing_epoch")?, "fencing epoch")?,
            sequence: to_u64(
                row.try_get::<i64, _>("fencing_sequence")?,
                "fencing sequence",
            )?,
        },
        policy_epoch: to_u64(row.try_get::<i64, _>("policy_epoch")?, "policy epoch")?,
        runtime: runtime_from_str(row.try_get::<String, _>("runtime")?.as_str())?,
        backend_version: row.try_get("backend_version")?,
        observed_state: state_from_str(row.try_get::<String, _>("observed_state")?.as_str())?,
        host_boot_id: row.try_get("host_boot_id")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn operation_outcome_from_row(row: &SqliteRow) -> Result<OperationOutcome, SupervisorError> {
    let status = status_from_str(row.try_get::<String, _>("status")?.as_str())?;
    let reason = row
        .try_get::<Option<String>, _>("reason")?
        .map(|reason| reason_from_str(&reason))
        .transpose()?
        .unwrap_or(OutcomeReason::InProgress);
    Ok(OperationOutcome {
        operation_id: OperationId::from_string(row.try_get::<String, _>("operation_id")?),
        sandbox_id: SandboxId::from_string(row.try_get::<String, _>("sandbox_id")?),
        kind: kind_from_str(row.try_get::<String, _>("kind")?.as_str())?,
        status,
        reason,
        non_ready_reason: row
            .try_get::<Option<String>, _>("non_ready_reason")?
            .map(|reason| non_ready_reason_from_str(&reason))
            .transpose()?,
        message: row.try_get("message")?,
        completed_at: row.try_get("updated_at")?,
    })
}

fn to_i64(value: u64, field: &str) -> Result<i64, SupervisorError> {
    i64::try_from(value)
        .map_err(|_| SupervisorError::InvalidLedgerValue(format!("{field} exceeds i64")))
}

fn to_u64(value: i64, field: &str) -> Result<u64, SupervisorError> {
    u64::try_from(value)
        .map_err(|_| SupervisorError::InvalidLedgerValue(format!("{field} is negative")))
}

macro_rules! string_enum_codec {
    ($to_fn:ident, $from_fn:ident, $ty:ty, $label:literal, { $($variant:ident => $str:literal),+ $(,)? }) => {
        fn $to_fn(value: $ty) -> &'static str {
            match value {
                $( <$ty>::$variant => $str, )+
            }
        }
        fn $from_fn(value: &str) -> Result<$ty, SupervisorError> {
            match value {
                $( $str => Ok(<$ty>::$variant), )+
                other => Err(SupervisorError::InvalidLedgerValue(format!(
                    "unknown {} {other}", $label
                ))),
            }
        }
    };
}

string_enum_codec!(runtime_to_str, runtime_from_str, RuntimeType, "runtime", {
    Firecracker => "firecracker",
    RemoteFirecracker => "remote-firecracker",
    Qemu => "qemu",
    GVisor => "gvisor",
});

string_enum_codec!(state_to_str, state_from_str, SandboxState, "sandbox state", {
    Pending => "pending",
    Scheduled => "scheduled",
    Preparing => "preparing",
    Booting => "booting",
    Running => "running",
    Suspending => "suspending",
    Suspended => "suspended",
    Resuming => "resuming",
    Stopped => "stopped",
    Destroying => "destroying",
    Destroyed => "destroyed",
    Failed => "failed",
});

string_enum_codec!(kind_to_str, kind_from_str, OperationKind, "operation kind", {
    Prepare => "prepare",
    Boot => "boot",
    Exec => "exec",
    Suspend => "suspend",
    Resume => "resume",
    Destroy => "destroy",
    Process => "process",
    Restore => "restore",
    Fork => "fork",
});

string_enum_codec!(status_to_str, status_from_str, OutcomeStatus, "outcome status", {
    Running => "running",
    Succeeded => "succeeded",
    Failed => "failed",
    Canceled => "canceled",
    TimedOut => "timed_out",
    RequiresReview => "requires_review",
});

string_enum_codec!(reason_to_str, reason_from_str, OutcomeReason, "outcome reason", {
    InProgress => "in_progress",
    Completed => "completed",
    BackendFailure => "backend_failure",
    CanceledByHost => "canceled_by_host",
    DeadlineExceeded => "deadline_exceeded",
    PartialCleanup => "partial_cleanup",
    SupervisorRestarted => "supervisor_restarted",
    ProcessExited => "process_exited",
    ProcessSignaled => "process_signaled",
    ProcessFailure => "process_failure",
    RestoreRejected => "restore_rejected",
});

string_enum_codec!(
    non_ready_reason_to_str,
    non_ready_reason_from_str,
    NonReadyReason,
    "non-ready reason",
    {
        Image => "image",
        Network => "network",
        Resource => "resource",
        Backend => "backend",
        Protocol => "protocol",
        Timeout => "timeout",
        Cleanup => "cleanup",
    }
);
