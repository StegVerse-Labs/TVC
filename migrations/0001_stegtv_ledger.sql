CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS policy_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_hash text NOT NULL UNIQUE,
  source text NOT NULL DEFAULT 'unknown',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workload_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL,
  subject text NOT NULL,
  repo text NOT NULL,
  ref text NULL,
  workflow_ref text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(provider, subject)
);

CREATE TABLE IF NOT EXISTS issued_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  jti text NOT NULL UNIQUE,
  issuer text NOT NULL,
  workload_id uuid NOT NULL REFERENCES workload_identities(id) ON DELETE RESTRICT,
  policy_version_id uuid NULL REFERENCES policy_versions(id) ON DELETE SET NULL,
  repo text NOT NULL,
  ref text NOT NULL,
  sha text NOT NULL,
  scope text NOT NULL,
  env text NOT NULL,
  mode text NULL,
  rev_epoch integer NOT NULL,
  iat timestamptz NOT NULL,
  exp timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  time timestamptz NOT NULL DEFAULT now(),
  event_type text NOT NULL,
  decision text NOT NULL,
  reason text NULL,
  workload_id uuid NOT NULL REFERENCES workload_identities(id) ON DELETE RESTRICT,
  issued_token_id uuid NULL REFERENCES issued_tokens(id) ON DELETE SET NULL,
  policy_version_id uuid NULL REFERENCES policy_versions(id) ON DELETE SET NULL,
  repo text NOT NULL,
  ref text NOT NULL,
  sha text NOT NULL,
  scope text NOT NULL,
  env text NOT NULL,
  request_id text NOT NULL,
  meta jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS ix_events_time ON execution_events(time DESC);
CREATE INDEX IF NOT EXISTS ix_events_repo_time ON execution_events(repo, time DESC);
CREATE INDEX IF NOT EXISTS ix_tokens_repo_time ON issued_tokens(repo, iat DESC);
CREATE INDEX IF NOT EXISTS ix_workloads_repo ON workload_identities(repo);
