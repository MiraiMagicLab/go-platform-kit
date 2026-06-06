-- Partition audit_logs by month using range partitioning on created_at.
-- This migration converts the existing flat table to a partitioned table.
-- Recommended: use pg_partman for ongoing partition management instead of manual partitions.
BEGIN;

CREATE TABLE audit_logs_partitioned (
  id UUID,
  user_id UUID,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL
) PARTITION BY RANGE (created_at);

-- Create partitions for the next 12 months
CREATE TABLE audit_logs_2026_06 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE audit_logs_2026_07 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE audit_logs_2026_08 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE audit_logs_2026_09 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE audit_logs_2026_10 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE audit_logs_2026_11 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE audit_logs_2026_12 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE audit_logs_2027_01 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE audit_logs_2027_02 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE audit_logs_2027_03 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');
CREATE TABLE audit_logs_2027_04 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2027-04-01') TO ('2027-05-01');
CREATE TABLE audit_logs_2027_05 PARTITION OF audit_logs_partitioned
  FOR VALUES FROM ('2027-05-01') TO ('2027-06-01');

-- Copy existing data
INSERT INTO audit_logs_partitioned
  SELECT * FROM audit_logs;

-- Swap tables
ALTER TABLE audit_logs RENAME TO audit_logs_old;
ALTER TABLE audit_logs_partitioned RENAME TO audit_logs;

COMMIT;

-- Indexes on new partitioned table (inherited by all partitions)
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Optional: drop old table after verifying data integrity
-- DROP TABLE IF EXISTS audit_logs_old;
