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

    // Every migration body must end with a terminator. The runner
    // interpolates the body directly before `COMMIT TRANSACTION;` in
    // `apply_one`, so a body whose last statement is missing its `;`
    // would silently chain with the COMMIT token, yielding a
    // confusing SurrealQL parse error at boot rather than a clear
    // "migration <name> is malformed" diagnostic. We reject up front
    // instead.
    for (name, body) in MIGRATIONS {
        if !body.trim_end().ends_with(';') {
            return Err(surrealdb::Error::thrown(format!(
                "migration {name} does not end with a `;` terminator; \
                 the runner concatenates `COMMIT TRANSACTION;` after the body, \
                 so a missing terminator silently chains the COMMIT token \
                 with the last statement — append `;` to fix"
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

/// Apply a single migration inside one SurrealDB transaction.
///
/// The transaction body lays the bookkeeping row down FIRST and the
/// migration's own statements second. That ordering matters: under a
/// concurrent-boot race the second binary's `CREATE schema_migration`
/// will fail on the UNIQUE index on `name` before any body statement
/// runs, which lets us distinguish a benign "the other binary already
/// applied this" from a genuine UNIQUE error inside the migration
/// body (e.g. a bad seed row hitting a UNIQUE index the migration
/// just defined). If the bookkeeping insert succeeds and the body
/// then fails for any reason, SurrealDB rolls back the bookkeeping
/// row too — there's never a `schema_migration` row claiming success
/// for a body that didn't land.
///
/// On the benign-race branch we reload the existing `schema_migration`
/// row and re-check its checksum: if the race partner committed a row
/// whose checksum disagrees with ours, the two binaries are shipping
/// divergent migration content and we must surface the same drift
/// error the main checksum path raises.
async fn apply_one(
    db: &Surreal<Any>,
    name: &str,
    body: &str,
    checksum: &str,
) -> Result<(), surrealdb::Error> {
    let applied_at = now_iso();
    let sql = format!(
        "BEGIN TRANSACTION;\n\
         CREATE schema_migration SET name = $name, checksum = $checksum, applied_at = $applied_at;\n\
         {body}\n\
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
        Err(e) if is_schema_migration_claim_collision(&e.to_string()) => {
            // Narrowed by `is_schema_migration_claim_collision` so this
            // arm only fires for UNIQUE failures that reference the
            // `schema_migration` table / `schema_migration_name_unique`
            // index. A migration body that defines its own UNIQUE
            // index and violates it propagates instead of getting
            // silently swallowed as a benign race. Structurally the
            // claim is still the first statement in the transaction
            // (see SQL above), but relying on statement ordering alone
            // is fragile — the explicit narrowing makes the
            // failure-mode partitioning unambiguous at the matcher.
            info!(
                migration = name,
                "Concurrent boot race detected — another binary won the schema_migration claim"
            );
            verify_race_partner_checksum(db, name, checksum).await
        }
        Err(e) => Err(e),
    }
}

/// Fetch the `schema_migration` row another binary just inserted under
/// our nose and compare its checksum against ours. Surfaces the same
/// `drift_error` the main checksum-mismatch path uses, so the two
/// failure modes look identical to operators reading the logs.
async fn verify_race_partner_checksum(
    db: &Surreal<Any>,
    name: &str,
    expected_checksum: &str,
) -> Result<(), surrealdb::Error> {
    let mut resp = db
        .query("SELECT name, checksum FROM schema_migration WHERE name = $name LIMIT 1")
        .bind(("name", name.to_string()))
        .await?
        .check()?;
    let rows: Vec<AppliedMigration> = resp.take(0)?;
    let partner = rows.into_iter().next().ok_or_else(|| {
        // If we hit UNIQUE on insert but the row isn't there on
        // read, something between us and SurrealDB ate it. That's
        // not a benign race — surface it loudly.
        surrealdb::Error::thrown(format!(
            "migration {name} hit UNIQUE on insert but no schema_migration row exists on re-read; \
             racing binary may have been killed mid-commit"
        ))
    })?;
    if partner.checksum != expected_checksum {
        return Err(drift_error(name, &partner.checksum, expected_checksum));
    }
    Ok(())
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

/// Narrows `is_unique_constraint_error` to the `schema_migration`
/// bookkeeping row only. The migration body sits inside the same
/// transaction (after the `CREATE schema_migration` claim) and could
/// itself raise a UNIQUE failure — e.g. a future migration that
/// defines a UNIQUE index and seeds rows that violate it. The
/// benign-race branch must not swallow those; only collisions that
/// reference the `schema_migration` table or its UNIQUE index count
/// as a concurrent-boot race. If SurrealDB's error message format ever
/// stops naming the table/index, this helper fails-closed (returns
/// false) and the genuine error propagates — never the other way.
fn is_schema_migration_claim_collision(message: &str) -> bool {
    is_unique_constraint_error(message)
        && (message.contains("schema_migration_name_unique")
            || message.contains("schema_migration"))
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
    fn every_embedded_migration_body_ends_with_semicolon() {
        // Locks the apply_one invariant at compile/test time: a future
        // .surql file that forgets its trailing `;` would silently chain
        // with the appended `COMMIT TRANSACTION;` at runtime, producing a
        // confusing syntax error. Catching it here means the failure mode
        // is a test failure with a clear migration name, not a boot
        // crash.
        for (name, body) in MIGRATIONS {
            assert!(
                body.trim_end().ends_with(';'),
                "migration {name} must end with a `;` terminator"
            );
        }
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

    #[test]
    fn schema_migration_claim_collision_narrows_to_meta_table() {
        // The benign-race branch must only fire for UNIQUE failures on the
        // schema_migration bookkeeping row. A body-level UNIQUE failure on
        // an unrelated table or index must NOT slot in — it propagates as
        // a real error.
        assert!(is_schema_migration_claim_collision(
            "Database index `schema_migration_name_unique` already contains 0001_initial_schema"
        ));
        assert!(is_schema_migration_claim_collision(
            "unique constraint failed on schema_migration"
        ));
        assert!(!is_schema_migration_claim_collision(
            "Database index `receipt_whatsapp_message_id_unique` already contains WAMSG-123"
        ));
        assert!(!is_schema_migration_claim_collision(
            "Database index `user_identity_provider_subject` already contains [credentials, foo@bar.com]"
        ));
        // Non-UNIQUE errors don't qualify regardless of message content.
        assert!(!is_schema_migration_claim_collision(
            "schema_migration: connection refused"
        ));
    }
}
