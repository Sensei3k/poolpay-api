//! Hand-rolled SurrealDB migration runner.
//!
//! Replaces the previous `define_tables` / `define_receipt_extensions` /
//! `define_inbox_table` / `define_auth_tables` chain of idempotent
//! `DEFINE … IF NOT EXISTS` statements with an ordered, append-only
//! migration history kept in a `schema_migration` meta table. Every
//! migration is a single `.surql` file under `migrations/` named with a
//! zero-padded ordinal (e.g. `0001_initial_schema.surql`); the runner
//! applies any unapplied files in lexicographic order at boot and
//! records the result so subsequent boots short-circuit.
//!
//! ## Why not refinery / sqlx-style framework
//!
//! Surreal's `BEGIN…COMMIT` semantics are different enough from
//! Postgres' that a generic Rust migration crate would either need a
//! Surreal-shaped driver wired in or would mis-handle DDL transactions.
//! Hand-rolling keeps the runner small, adds zero new dependencies
//! (`sha2` was already in `Cargo.toml`), and gives us full control over
//! the SurrealQL execution path — mirroring the same "inline pattern
//! over a crate" decision made in PR #66 for the transactional
//! create-user-with-grants endpoint.
//!
//! ## Guarantees
//!
//! 1. **Ordered apply.** Files are sorted lexicographically — pad the
//!    ordinal correctly (`0001`, `0010`, `0100`) or the apply order will
//!    not match the human-readable order.
//! 2. **Idempotent apply.** A migration whose name already appears in
//!    `schema_migration` with a matching checksum is skipped. The
//!    checksum is `sha256(file_bytes)`; the `0001_initial_schema.surql`
//!    file's bytes are the canonical form.
//! 3. **Drift detection.** If a name is already applied but the file's
//!    current checksum differs from the stored one, the runner refuses
//!    to proceed and returns an error. Migrations are immutable history;
//!    edit a typo by adding a follow-up migration, not by rewriting an
//!    applied one.
//! 4. **Skip detection.** If the lexicographically-sorted file list
//!    contains an *unapplied* migration that precedes an *applied* one,
//!    the runner refuses to proceed. This catches a common foot-shoot
//!    where someone adds `0002a_something.surql` between two existing
//!    migrations whose later sibling is already in production.
//! 5. **Atomic apply.** Each migration body is wrapped in
//!    `BEGIN TRANSACTION; … COMMIT TRANSACTION;` and the
//!    `schema_migration` insert runs inside the same transaction, so a
//!    failure midway rolls back both the schema change and the
//!    bookkeeping row.

use sha2::{Digest, Sha256};
use surrealdb::engine::any::Any;
use surrealdb::Surreal;
use surrealdb_types::SurrealValue;
use tracing::{info, warn};

use crate::api::models::now_iso;
use crate::db::is_unique_constraint_error;

/// Embedded migration corpus. New migrations land here in
/// lexicographically-ordered insertion. Compile-time `include_str!`
/// embeds the file content in the binary so the runner does not depend
/// on a working directory layout at runtime (deployed binaries on
/// Fly/Render can ship without a sidecar `migrations/` directory).
///
/// Adding a migration: drop the `.surql` file under `migrations/`, then
/// append a new entry to this array. The `name` must match the filename
/// (without extension) so the bookkeeping row stays human-aligned with
/// the file on disk.
const MIGRATIONS: &[(&str, &str)] = &[(
    "0001_initial_schema",
    include_str!("../migrations/0001_initial_schema.surql"),
)];

#[derive(Debug, serde::Deserialize, SurrealValue)]
struct AppliedMigration {
    name: String,
    checksum: String,
}

/// Apply every pending migration in order, recording each result in the
/// `schema_migration` meta table. Returns once the in-memory migration
/// list is exhausted (idempotent on a fully-applied DB).
pub async fn apply_pending(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    debug_assert!(
        MIGRATIONS.windows(2).all(|w| w[0].0 < w[1].0),
        "MIGRATIONS must be strictly sorted by name — found out-of-order entries"
    );
    // Runtime guard (in addition to the debug_assert) so a release build
    // with a misordered array fails fast at startup rather than silently
    // apply migrations in the wrong order.
    for w in MIGRATIONS.windows(2) {
        if w[0].0 >= w[1].0 {
            return Err(surrealdb::Error::thrown(format!(
                "MIGRATIONS array is not strictly sorted: '{}' must come before '{}'",
                w[0].0, w[1].0
            )));
        }
    }

    ensure_meta_table(db).await?;
    let applied = load_applied(db).await?;

    enforce_no_skipped(MIGRATIONS, &applied)?;

    let mut applied_count: usize = 0;
    for (name, body) in MIGRATIONS {
        let checksum = sha256_hex(body.as_bytes());
        if let Some(existing) = applied.iter().find(|m| m.name == *name) {
            if existing.checksum != checksum {
                return Err(drift_error(name, &existing.checksum, &checksum));
            }
            continue;
        }
        apply_one(db, name, body, &checksum).await?;
        applied_count += 1;
    }

    if applied_count > 0 {
        info!(applied = applied_count, "Applied pending migrations");
    }
    Ok(())
}

/// Define the bookkeeping table itself. This is the only piece of
/// `DEFINE … IF NOT EXISTS` left in Rust — it has to exist before we
/// can read the applied-migrations list. UNIQUE on `name` so a bug in
/// the runner that double-records the same migration becomes a hard
/// error rather than silent duplication.
async fn ensure_meta_table(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    db.query(
        "DEFINE TABLE IF NOT EXISTS schema_migration SCHEMAFULL;
         DEFINE FIELD IF NOT EXISTS name ON schema_migration TYPE string;
         DEFINE FIELD IF NOT EXISTS checksum ON schema_migration TYPE string;
         DEFINE FIELD IF NOT EXISTS applied_at ON schema_migration TYPE string;
         DEFINE INDEX IF NOT EXISTS schema_migration_name_unique
             ON schema_migration FIELDS name UNIQUE;",
    )
    .await?
    .check()?;
    Ok(())
}

async fn load_applied(db: &Surreal<Any>) -> Result<Vec<AppliedMigration>, surrealdb::Error> {
    let mut resp = db
        .query("SELECT name, checksum FROM schema_migration ORDER BY name ASC")
        .await?
        .check()?;
    let rows: Vec<AppliedMigration> = resp.take(0)?;
    Ok(rows)
}

/// Apply a single migration inside one SurrealDB transaction: the body
/// statements first, then the `schema_migration` insert. SurrealDB
/// cancels the whole transaction on any failure, so a half-applied
/// migration cannot leave behind a `schema_migration` row that claims
/// success.
async fn apply_one(
    db: &Surreal<Any>,
    name: &str,
    body: &str,
    checksum: &str,
) -> Result<(), surrealdb::Error> {
    let applied_at = now_iso();
    let sql = format!(
        "BEGIN TRANSACTION;\n\
         {body}\n\
         CREATE schema_migration SET name = $name, checksum = $checksum, applied_at = $applied_at;\n\
         COMMIT TRANSACTION;"
    );
    let result = db
        .query(sql)
        .bind(("name", name.to_string()))
        .bind(("checksum", checksum.to_string()))
        .bind(("applied_at", applied_at))
        .await
        .and_then(|r| r.check());
    match result {
        Ok(_) => {
            info!(migration = name, "Applied migration");
            Ok(())
        }
        Err(e) if is_unique_constraint_error(&e.to_string()) => {
            // Concurrent boot race: another binary applied this same
            // migration between our `load_applied()` and our CREATE.
            // The UNIQUE index on `schema_migration.name` caught it, so
            // the other binary's work is durable and ours can no-op.
            // The next iteration of `apply_pending`'s loop will skip
            // this name on the cached `applied` set — fine because the
            // only remaining work is downstream migrations, which the
            // race partner has equal claim to apply.
            info!(
                migration = name,
                "Concurrent boot race detected — migration was applied by another binary"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Refuse to proceed if the applied set isn't a contiguous prefix of
/// the on-disk file list. Without this guard, inserting
/// `0002a_xxx.surql` between an applied `0002` and an applied `0003`
/// would silently apply `0002a` *after* `0003`, which violates the
/// ordering invariant any subsequent migration may rely on.
fn enforce_no_skipped(
    migrations: &[(&str, &str)],
    applied: &[AppliedMigration],
) -> Result<(), surrealdb::Error> {
    // First: every applied row must be a migration this binary knows
    // about. An unknown applied row means either (a) a migration file
    // was deleted (history rewrite — destructive) or (b) the DB was
    // migrated by a newer binary version (downgrade). Both warrant a
    // hard refusal before we touch any further state.
    for row in applied {
        if !migrations.iter().any(|(name, _)| *name == row.name) {
            warn!(
                migration = %row.name,
                "schema_migration row not known to this binary — refusing to apply"
            );
            return Err(unknown_error(&row.name));
        }
    }

    // Second: applied set must form a contiguous prefix of the known
    // migrations list — no later migration may be applied while an
    // earlier one is unapplied.
    let mut first_unapplied: Option<&str> = None;
    for (name, _) in migrations {
        let is_applied = applied.iter().any(|m| m.name == *name);
        if is_applied {
            if let Some(unapplied) = first_unapplied {
                warn!(
                    unapplied,
                    later_applied = *name,
                    "Out-of-order migration detected — refusing to apply"
                );
                return Err(skip_error(unapplied, name));
            }
        } else if first_unapplied.is_none() {
            first_unapplied = Some(name);
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex_encode(&digest)
}

/// Lowercase hex encoder. Lifted inline (rather than pulling in `hex`)
/// to keep the migration runner dependency-free beyond what the crate
/// already uses (`sha2`).
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn drift_error(name: &str, expected: &str, actual: &str) -> surrealdb::Error {
    surrealdb::Error::thrown(format!(
        "migration {name} checksum drift — stored {expected}, file is now {actual}; \
         create a follow-up migration instead of editing an applied one"
    ))
}

fn skip_error(unapplied: &str, later_applied: &str) -> surrealdb::Error {
    surrealdb::Error::thrown(format!(
        "migration {unapplied} is unapplied but the later migration {later_applied} \
         is already applied; migrations must apply in lexicographic order — \
         either roll back {later_applied} or rename {unapplied} so it sorts after it"
    ))
}

fn unknown_error(name: &str) -> surrealdb::Error {
    surrealdb::Error::thrown(format!(
        "schema_migration row {name} is not known to this binary; either a \
         migration file was deleted (do not delete applied migrations — they \
         are immutable history) or this DB was migrated by a newer binary \
         version and this one is being run as a downgrade"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // Empty input → well-known SHA-256 digest.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn enforce_no_skipped_passes_when_prefix_applied() {
        let migrations: &[(&str, &str)] = &[("0001_a", "x"), ("0002_b", "y"), ("0003_c", "z")];
        let applied = vec![AppliedMigration {
            name: "0001_a".into(),
            checksum: "x".into(),
        }];
        enforce_no_skipped(migrations, &applied).expect("contiguous prefix must pass");
    }

    #[test]
    fn migrations_array_is_strictly_sorted() {
        // Lock the sort-order invariant the module doc claims — if a
        // future maintainer appends an out-of-order entry, this test
        // fires before the runtime guard ever has to.
        for w in MIGRATIONS.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "MIGRATIONS must be strictly sorted: '{}' should come before '{}'",
                w[0].0,
                w[1].0
            );
        }
    }

    #[test]
    fn enforce_no_skipped_fails_on_gap_in_history() {
        let migrations: &[(&str, &str)] = &[("0001_a", "x"), ("0002_b", "y"), ("0003_c", "z")];
        // 0001 unapplied, 0002 applied — must refuse.
        let applied = vec![AppliedMigration {
            name: "0002_b".into(),
            checksum: "y".into(),
        }];
        let err =
            enforce_no_skipped(migrations, &applied).expect_err("gap in applied history must fail");
        assert!(err.to_string().contains("0001_a"));
    }
}
