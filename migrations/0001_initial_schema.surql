-- 0001_initial_schema
--
-- Captures every DEFINE statement that previously lived in
-- `src/db.rs::define_tables`, `define_receipt_extensions`,
-- `define_inbox_table`, and `define_auth_tables`. The IF NOT EXISTS
-- clauses are retained so the first run of the migration runner against
-- a DB that was previously bootstrapped through the legacy path lands
-- as a no-op write: the rows materialise in `schema_migration` without
-- conflicting with the already-defined schema.
--
-- Subsequent migrations may drop the IF NOT EXISTS guards for net-new
-- objects, since their definitions will not collide with anything
-- pre-existing.

-- Domain tables (SCHEMALESS so fixture inserts and incremental field
-- additions both work without a destructive backfill).
DEFINE TABLE IF NOT EXISTS group SCHEMALESS;
DEFINE TABLE IF NOT EXISTS member SCHEMALESS;
DEFINE TABLE IF NOT EXISTS cycle SCHEMALESS;
DEFINE TABLE IF NOT EXISTS payment SCHEMALESS;
DEFINE TABLE IF NOT EXISTS group_link SCHEMALESS;
DEFINE TABLE IF NOT EXISTS receipt SCHEMALESS;

-- Receipt: slice 5 fields + server-stamped timestamps.
DEFINE FIELD IF NOT EXISTS raw_image_url ON receipt TYPE option<string>;
DEFINE FIELD IF NOT EXISTS rejection_reason ON receipt TYPE option<string>;
DEFINE FIELD IF NOT EXISTS ingested_at ON receipt TYPE option<string>;

-- Receipt indexes.
DEFINE INDEX IF NOT EXISTS receipt_whatsapp_message_id_unique
    ON receipt FIELDS whatsapp_message_id UNIQUE;
DEFINE INDEX IF NOT EXISTS receipt_sender_received
    ON receipt FIELDS sender_phone, received_at;
DEFINE INDEX IF NOT EXISTS receipt_status_received
    ON receipt FIELDS status, received_at;
DEFINE INDEX IF NOT EXISTS receipt_status_ingested
    ON receipt FIELDS status, ingested_at;

-- inbox_item (SCHEMAFULL — `kind` vocabulary is contract-bearing).
DEFINE TABLE IF NOT EXISTS inbox_item SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON inbox_item TYPE string;
DEFINE FIELD IF NOT EXISTS kind ON inbox_item TYPE string
    ASSERT $value IN ['receipt_confirmed', 'cycle_starting', 'payout_scheduled', 'admin_message', 'overdue'];
DEFINE FIELD IF NOT EXISTS title ON inbox_item TYPE string;
DEFINE FIELD IF NOT EXISTS body ON inbox_item TYPE string;
DEFINE FIELD IF NOT EXISTS pool_id ON inbox_item TYPE option<string>;
DEFINE FIELD IF NOT EXISTS cycle_id ON inbox_item TYPE option<string>;
DEFINE FIELD IF NOT EXISTS receipt_id ON inbox_item TYPE option<string>;
DEFINE FIELD IF NOT EXISTS read_at ON inbox_item TYPE option<string>;
DEFINE FIELD IF NOT EXISTS created_at ON inbox_item TYPE string;
DEFINE INDEX IF NOT EXISTS inbox_item_user_created
    ON inbox_item FIELDS user_id, created_at;
DEFINE INDEX IF NOT EXISTS inbox_item_user_unread
    ON inbox_item FIELDS user_id, read_at;

-- Auth tables (SCHEMAFULL — security-critical shape enforced at the DB
-- layer rather than relying on application checks alone).
DEFINE TABLE IF NOT EXISTS user SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS email ON user TYPE string;
DEFINE FIELD IF NOT EXISTS email_normalised ON user TYPE string;
DEFINE FIELD IF NOT EXISTS password_hash ON user TYPE option<string>;
DEFINE FIELD IF NOT EXISTS role ON user TYPE string
    ASSERT $value IN ['super_admin', 'admin', 'member'];
DEFINE FIELD IF NOT EXISTS status ON user TYPE string ASSERT $value IN ['active', 'disabled'];
DEFINE FIELD IF NOT EXISTS token_version ON user TYPE int;
DEFINE FIELD IF NOT EXISTS must_reset_password ON user TYPE bool;
DEFINE FIELD IF NOT EXISTS version ON user TYPE int;
UPDATE user SET version = 1 WHERE version IS NONE;
DEFINE FIELD IF NOT EXISTS created_at ON user TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON user TYPE string;
DEFINE FIELD IF NOT EXISTS deleted_at ON user TYPE option<string>;
DEFINE INDEX IF NOT EXISTS user_email_normalised ON user FIELDS email_normalised;

DEFINE TABLE IF NOT EXISTS user_identity SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON user_identity TYPE string;
DEFINE FIELD IF NOT EXISTS provider ON user_identity TYPE string
    ASSERT $value IN ['google', 'github', 'apple', 'credentials'];
DEFINE FIELD IF NOT EXISTS provider_subject ON user_identity TYPE string;
DEFINE FIELD IF NOT EXISTS email_at_link ON user_identity TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON user_identity TYPE string;
DEFINE INDEX IF NOT EXISTS user_identity_provider_subject
    ON user_identity FIELDS provider, provider_subject UNIQUE;

DEFINE TABLE IF NOT EXISTS auth_event SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON auth_event TYPE option<string>;
DEFINE FIELD IF NOT EXISTS actor_id ON auth_event TYPE option<string>;
DEFINE FIELD IF NOT EXISTS event_type ON auth_event TYPE string;
DEFINE FIELD IF NOT EXISTS ip ON auth_event TYPE option<string>;
DEFINE FIELD IF NOT EXISTS user_agent ON auth_event TYPE option<string>;
DEFINE FIELD IF NOT EXISTS success ON auth_event TYPE bool;
DEFINE FIELD IF NOT EXISTS reason ON auth_event TYPE option<string>;
DEFINE FIELD IF NOT EXISTS created_at ON auth_event TYPE string;

DEFINE TABLE IF NOT EXISTS refresh_token SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON refresh_token TYPE string;
DEFINE FIELD IF NOT EXISTS hashed_token ON refresh_token TYPE string;
DEFINE FIELD IF NOT EXISTS family_id ON refresh_token TYPE string;
DEFINE FIELD IF NOT EXISTS issued_at ON refresh_token TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON refresh_token TYPE string;
DEFINE FIELD IF NOT EXISTS revoked_at ON refresh_token TYPE option<string>;
DEFINE FIELD IF NOT EXISTS replaced_by ON refresh_token TYPE option<string>;
DEFINE INDEX IF NOT EXISTS refresh_token_hashed
    ON refresh_token FIELDS hashed_token UNIQUE;
DEFINE INDEX IF NOT EXISTS refresh_token_family ON refresh_token FIELDS family_id;
DEFINE INDEX IF NOT EXISTS refresh_token_user ON refresh_token FIELDS user_id;

DEFINE TABLE IF NOT EXISTS group_admin SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON group_admin TYPE string;
DEFINE FIELD IF NOT EXISTS group_id ON group_admin TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON group_admin TYPE string;
DEFINE FIELD IF NOT EXISTS created_by ON group_admin TYPE string;
DEFINE INDEX IF NOT EXISTS group_admin_user_group
    ON group_admin FIELDS user_id, group_id UNIQUE;
DEFINE INDEX IF NOT EXISTS group_admin_group ON group_admin FIELDS group_id;
