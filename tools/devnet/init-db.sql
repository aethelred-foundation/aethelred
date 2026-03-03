-- Aethelred DevNet Database Initialization
-- PostgreSQL schema for indexing and analytics

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================
-- Blocks
-- ============================================

CREATE TABLE blocks (
    id BIGSERIAL PRIMARY KEY,
    height BIGINT NOT NULL UNIQUE,
    block_hash BYTEA NOT NULL UNIQUE,
    prev_block_hash BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    proposer_address BYTEA NOT NULL,
    tx_count INTEGER NOT NULL DEFAULT 0,
    gas_used BIGINT NOT NULL DEFAULT 0,
    state_root BYTEA NOT NULL,
    tx_root BYTEA NOT NULL,
    compute_root BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_blocks_height ON blocks(height DESC);
CREATE INDEX idx_blocks_timestamp ON blocks(timestamp DESC);
CREATE INDEX idx_blocks_proposer ON blocks(proposer_address);

-- ============================================
-- Transactions
-- ============================================

CREATE TABLE transactions (
    id BIGSERIAL PRIMARY KEY,
    tx_hash BYTEA NOT NULL UNIQUE,
    block_height BIGINT NOT NULL REFERENCES blocks(height),
    tx_index INTEGER NOT NULL,
    tx_type SMALLINT NOT NULL,
    sender_address BYTEA NOT NULL,
    nonce BIGINT NOT NULL,
    gas_price BIGINT NOT NULL,
    gas_limit BIGINT NOT NULL,
    gas_used BIGINT,
    status SMALLINT NOT NULL DEFAULT 0, -- 0=pending, 1=success, 2=failed
    error_message TEXT,
    raw_tx BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tx_block_height ON transactions(block_height);
CREATE INDEX idx_tx_sender ON transactions(sender_address);
CREATE INDEX idx_tx_type ON transactions(tx_type);
CREATE INDEX idx_tx_status ON transactions(status);
CREATE INDEX idx_tx_created_at ON transactions(created_at DESC);

-- ============================================
-- Compute Jobs
-- ============================================

CREATE TABLE compute_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id BYTEA NOT NULL UNIQUE,
    tx_hash BYTEA NOT NULL REFERENCES transactions(tx_hash),
    requester_address BYTEA NOT NULL,
    model_hash BYTEA NOT NULL,
    input_hash BYTEA NOT NULL,
    output_hash BYTEA,
    verification_method SMALLINT NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0, -- 0=pending, 1=computing, 2=verifying, 3=sealed, 4=failed
    min_attestations INTEGER NOT NULL DEFAULT 2,
    received_attestations INTEGER NOT NULL DEFAULT 0,
    max_latency_ms INTEGER NOT NULL,
    actual_latency_ms INTEGER,
    max_fee NUMERIC(78, 0) NOT NULL,
    actual_fee NUMERIC(78, 0),
    compliance_frameworks TEXT[],
    data_residency VARCHAR(2),
    audit_required BOOLEAN NOT NULL DEFAULT FALSE,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_jobs_requester ON compute_jobs(requester_address);
CREATE INDEX idx_jobs_model ON compute_jobs(model_hash);
CREATE INDEX idx_jobs_status ON compute_jobs(status);
CREATE INDEX idx_jobs_submitted_at ON compute_jobs(submitted_at DESC);

-- ============================================
-- Digital Seals
-- ============================================

CREATE TABLE digital_seals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    seal_id BYTEA NOT NULL UNIQUE,
    job_id BYTEA NOT NULL REFERENCES compute_jobs(job_id),
    tx_hash BYTEA NOT NULL REFERENCES transactions(tx_hash),
    block_height BIGINT NOT NULL REFERENCES blocks(height),
    model_commitment BYTEA NOT NULL,
    input_commitment BYTEA NOT NULL,
    output_commitment BYTEA NOT NULL,
    requester_address BYTEA NOT NULL,
    verification_method SMALLINT NOT NULL,
    validator_count INTEGER NOT NULL,
    validators BYTEA[] NOT NULL,
    has_zkml_proof BOOLEAN NOT NULL DEFAULT FALSE,
    purpose VARCHAR(255),
    compliance_frameworks TEXT[],
    data_residency VARCHAR(2),
    timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_seals_job_id ON digital_seals(job_id);
CREATE INDEX idx_seals_requester ON digital_seals(requester_address);
CREATE INDEX idx_seals_block_height ON digital_seals(block_height);
CREATE INDEX idx_seals_timestamp ON digital_seals(timestamp DESC);

-- ============================================
-- TEE Attestations
-- ============================================

CREATE TABLE tee_attestations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id BYTEA NOT NULL REFERENCES compute_jobs(job_id),
    validator_address BYTEA NOT NULL,
    platform SMALLINT NOT NULL, -- 1=Nitro, 2=SGX, 3=SEV
    attestation_doc BYTEA NOT NULL,
    enclave_hash BYTEA NOT NULL,
    output_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_attestations_job ON tee_attestations(job_id);
CREATE INDEX idx_attestations_validator ON tee_attestations(validator_address);

-- ============================================
-- Validators
-- ============================================

CREATE TABLE validators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    operator_address BYTEA NOT NULL UNIQUE,
    consensus_pubkey BYTEA NOT NULL,
    hybrid_pubkey_ecdsa BYTEA NOT NULL,
    hybrid_pubkey_dilithium BYTEA NOT NULL,
    moniker VARCHAR(255) NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0, -- 0=unbonded, 1=unbonding, 2=bonded
    tokens NUMERIC(78, 0) NOT NULL DEFAULT 0,
    delegator_shares NUMERIC(78, 0) NOT NULL DEFAULT 0,
    commission_rate NUMERIC(10, 8) NOT NULL,
    has_tee BOOLEAN NOT NULL DEFAULT FALSE,
    tee_platform SMALLINT,
    has_gpu BOOLEAN NOT NULL DEFAULT FALSE,
    gpu_model VARCHAR(100),
    memory_gb INTEGER,
    compute_units INTEGER,
    jobs_completed BIGINT NOT NULL DEFAULT 0,
    jobs_failed BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_validators_status ON validators(status);
CREATE INDEX idx_validators_tokens ON validators(tokens DESC);

-- ============================================
-- Models Registry
-- ============================================

CREATE TABLE models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id VARCHAR(255) NOT NULL UNIQUE,
    model_hash BYTEA NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    owner_address BYTEA NOT NULL,
    input_schema JSONB NOT NULL,
    output_schema JSONB NOT NULL,
    verification_method SMALLINT NOT NULL,
    compliance_frameworks TEXT[],
    circuit_hash BYTEA,
    verifying_key_hash BYTEA,
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_models_owner ON models(owner_address);
CREATE INDEX idx_models_trusted ON models(is_trusted);

-- ============================================
-- Compliance Audit Log
-- ============================================

CREATE TABLE compliance_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL, -- 'job', 'seal', 'transaction'
    entity_id BYTEA NOT NULL,
    framework VARCHAR(50) NOT NULL,
    check_name VARCHAR(255) NOT NULL,
    passed BOOLEAN NOT NULL,
    details TEXT,
    actor_address BYTEA,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_entity ON compliance_audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_framework ON compliance_audit_log(framework);
CREATE INDEX idx_audit_timestamp ON compliance_audit_log(timestamp DESC);

-- ============================================
-- Account Balances (Cached)
-- ============================================

CREATE TABLE account_balances (
    address BYTEA NOT NULL,
    denom VARCHAR(50) NOT NULL,
    amount NUMERIC(78, 0) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (address, denom)
);

CREATE INDEX idx_balances_amount ON account_balances(denom, amount DESC);

-- ============================================
-- Statistics (Materialized)
-- ============================================

CREATE TABLE stats_daily (
    date DATE NOT NULL PRIMARY KEY,
    total_blocks BIGINT NOT NULL DEFAULT 0,
    total_transactions BIGINT NOT NULL DEFAULT 0,
    total_jobs_submitted BIGINT NOT NULL DEFAULT 0,
    total_jobs_completed BIGINT NOT NULL DEFAULT 0,
    total_seals_created BIGINT NOT NULL DEFAULT 0,
    total_gas_used NUMERIC(78, 0) NOT NULL DEFAULT 0,
    total_fees_collected NUMERIC(78, 0) NOT NULL DEFAULT 0,
    avg_job_latency_ms NUMERIC(10, 2),
    active_validators INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- Functions
-- ============================================

-- Update stats on new block
CREATE OR REPLACE FUNCTION update_daily_stats()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO stats_daily (date, total_blocks, total_transactions, total_gas_used)
    VALUES (DATE(NEW.timestamp), 1, NEW.tx_count, NEW.gas_used)
    ON CONFLICT (date)
    DO UPDATE SET
        total_blocks = stats_daily.total_blocks + 1,
        total_transactions = stats_daily.total_transactions + EXCLUDED.total_transactions,
        total_gas_used = stats_daily.total_gas_used + EXCLUDED.total_gas_used;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_stats_on_block
AFTER INSERT ON blocks
FOR EACH ROW EXECUTE FUNCTION update_daily_stats();

-- Update validator stats on attestation
CREATE OR REPLACE FUNCTION update_validator_job_stats()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE validators
    SET jobs_completed = jobs_completed + 1,
        updated_at = NOW()
    WHERE operator_address = NEW.validator_address;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_validator_stats
AFTER INSERT ON tee_attestations
FOR EACH ROW EXECUTE FUNCTION update_validator_job_stats();

-- ============================================
-- Views
-- ============================================

-- Recent blocks view
CREATE VIEW recent_blocks AS
SELECT
    b.height,
    encode(b.block_hash, 'hex') as block_hash,
    b.timestamp,
    b.tx_count,
    b.gas_used,
    v.moniker as proposer
FROM blocks b
LEFT JOIN validators v ON b.proposer_address = v.operator_address
ORDER BY b.height DESC
LIMIT 100;

-- Recent transactions view
CREATE VIEW recent_transactions AS
SELECT
    encode(t.tx_hash, 'hex') as tx_hash,
    t.block_height,
    t.tx_type,
    encode(t.sender_address, 'hex') as sender,
    t.gas_used,
    CASE t.status
        WHEN 0 THEN 'pending'
        WHEN 1 THEN 'success'
        WHEN 2 THEN 'failed'
    END as status,
    t.created_at
FROM transactions t
ORDER BY t.created_at DESC
LIMIT 100;

-- Active jobs view
CREATE VIEW active_jobs AS
SELECT
    encode(j.job_id, 'hex') as job_id,
    encode(j.requester_address, 'hex') as requester,
    encode(j.model_hash, 'hex') as model_hash,
    CASE j.verification_method
        WHEN 1 THEN 'TEE_ONLY'
        WHEN 2 THEN 'ZKML_ONLY'
        WHEN 3 THEN 'HYBRID'
        WHEN 4 THEN 'MPC'
    END as verification_method,
    CASE j.status
        WHEN 0 THEN 'pending'
        WHEN 1 THEN 'computing'
        WHEN 2 THEN 'verifying'
        WHEN 3 THEN 'sealed'
        WHEN 4 THEN 'failed'
    END as status,
    j.received_attestations,
    j.min_attestations,
    j.submitted_at
FROM compute_jobs j
WHERE j.status < 3
ORDER BY j.submitted_at DESC;

COMMENT ON DATABASE aethelred IS 'Aethelred DevNet Indexer Database';
