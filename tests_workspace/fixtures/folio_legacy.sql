-- Schema from the published Folio b9eb589; no customer data.
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, mfa_secret TEXT, mfa_last_step INTEGER NOT NULL DEFAULT -1, locale TEXT NOT NULL DEFAULT 'fr');
CREATE TABLE sessions (
          token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires REAL NOT NULL);
CREATE TABLE cases (
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'open', priority TEXT NOT NULL DEFAULT 'medium',
          assignee_id INTEGER REFERENCES users(id), created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, revision INTEGER NOT NULL DEFAULT 1);
CREATE TABLE analyses (
          id TEXT PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), filename TEXT NOT NULL,
          sha256 TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', subject TEXT NOT NULL DEFAULT '',
          result TEXT, error TEXT, source BLOB, created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, finished_at TEXT, source_ref TEXT, size INTEGER NOT NULL DEFAULT 0, ingestion_source TEXT NOT NULL DEFAULT 'upload', metadata TEXT NOT NULL DEFAULT '{}', owner_scope TEXT NOT NULL DEFAULT 'community', auto_title TEXT);
CREATE TABLE iocs (
          id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL,
          verdict TEXT NOT NULL DEFAULT 'unreviewed', UNIQUE(kind,value));
CREATE TABLE analysis_iocs (
          analysis_id TEXT NOT NULL REFERENCES analyses(id), ioc_id INTEGER NOT NULL REFERENCES iocs(id),
          PRIMARY KEY(analysis_id,ioc_id));
CREATE TABLE notes (
          id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
          author_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE events (
          id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), case_id INTEGER REFERENCES cases(id),
          action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE login_attempts (
          identity TEXT PRIMARY KEY, count INTEGER NOT NULL, window REAL NOT NULL);
CREATE TABLE mfa_challenges (
          token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires REAL NOT NULL);
CREATE TABLE mfa_pending (
          user_id INTEGER PRIMARY KEY REFERENCES users(id), secret TEXT NOT NULL,
          session_token TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE mfa_recovery (
          user_id INTEGER NOT NULL REFERENCES users(id), digest TEXT NOT NULL,
          PRIMARY KEY(user_id,digest));
CREATE TABLE api_tokens (
        id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL,
        created_at REAL NOT NULL, expires REAL NOT NULL);
CREATE TABLE evidence_attachments (
        analysis_id TEXT NOT NULL REFERENCES analyses(id), position INTEGER NOT NULL,
        storage_key TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
        PRIMARY KEY(analysis_id,position));
CREATE TABLE jobs (
        id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL UNIQUE REFERENCES analyses(id),
        state TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3, available_at REAL NOT NULL DEFAULT 0,
        lease_until REAL, lease_token TEXT, error TEXT, created_at REAL NOT NULL,
        updated_at REAL NOT NULL, idempotency_key TEXT, created_by INTEGER NOT NULL REFERENCES users(id),
        UNIQUE(created_by,idempotency_key));
CREATE TABLE worker_heartbeats (id TEXT PRIMARY KEY, seen REAL NOT NULL);
CREATE TABLE analyst_decisions (
          id INTEGER PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id),
          action TEXT NOT NULL CHECK(action IN ('decided','reopened')),
          verdict TEXT, confidence INTEGER, justification TEXT NOT NULL,
          actor_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE campaigns (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          tags TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'active', verdict TEXT,
          created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, deleted_at TEXT);
CREATE TABLE campaign_cases (
          campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
          case_id INTEGER NOT NULL REFERENCES cases(id),
          PRIMARY KEY(campaign_id,case_id));
CREATE TABLE campaign_events (
          campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
          event_id INTEGER NOT NULL REFERENCES events(id), PRIMARY KEY(campaign_id,event_id));
CREATE TABLE analysis_signals (
          analysis_id TEXT NOT NULL REFERENCES analyses(id), kind TEXT NOT NULL, value TEXT NOT NULL,
          PRIMARY KEY(analysis_id,kind,value));
CREATE TABLE analysis_indexed (
          analysis_id TEXT PRIMARY KEY REFERENCES analyses(id));
CREATE TABLE enrichments (
        id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id),
        provider TEXT NOT NULL, action TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
        status TEXT NOT NULL, result TEXT NOT NULL, external_id TEXT,
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, poll_after REAL NOT NULL DEFAULT 0,
        request_id TEXT UNIQUE, request_fingerprint TEXT NOT NULL, polls INTEGER NOT NULL DEFAULT 0);
CREATE TABLE enrichment_attempts (
        provider TEXT NOT NULL, requested_at REAL NOT NULL);
CREATE TABLE integration_health (
        provider TEXT PRIMARY KEY, result TEXT NOT NULL, checked_at TEXT NOT NULL);
CREATE TABLE case_actions (
          id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
          title TEXT NOT NULL, owner_id INTEGER REFERENCES users(id), due_date TEXT,
          status TEXT NOT NULL DEFAULT 'todo', proof TEXT NOT NULL DEFAULT '',
          revision INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE reporter_replies (
          id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
          analysis_id TEXT REFERENCES analyses(id), recipient TEXT NOT NULL, subject TEXT NOT NULL,
          body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', revision INTEGER NOT NULL DEFAULT 1,
          created_by INTEGER NOT NULL REFERENCES users(id), sent_by INTEGER REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          accepted_at TEXT, transport_error TEXT, reconciliation_proof TEXT NOT NULL DEFAULT '', resolved_by INTEGER REFERENCES users(id), resolved_at TEXT);
CREATE TABLE intelligence_links (
          id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id), campaign_id INTEGER REFERENCES campaigns(id),
          title TEXT NOT NULL, source TEXT NOT NULL, facts TEXT NOT NULL, counter_evidence TEXT NOT NULL DEFAULT '',
          hypothesis TEXT NOT NULL DEFAULT '', confidence INTEGER NOT NULL DEFAULT 0,
          observed_at TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
          created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX analyses_case ON analyses(case_id);
CREATE INDEX events_case ON events(case_id);
CREATE INDEX jobs_ready ON jobs(state,available_at);
CREATE INDEX decisions_analysis ON analyst_decisions(analysis_id,id DESC);
CREATE INDEX campaign_cases_case ON campaign_cases(case_id,campaign_id);
CREATE INDEX signals_value ON analysis_signals(kind,value,analysis_id);
CREATE INDEX analyses_created ON analyses(created_at DESC,id DESC);
CREATE INDEX analysis_iocs_ioc ON analysis_iocs(ioc_id,analysis_id);
CREATE INDEX enrichment_analysis ON enrichments(analysis_id,created_at DESC);
CREATE INDEX actions_case ON case_actions(case_id,status,due_date);
CREATE INDEX replies_case ON reporter_replies(case_id,id DESC);
CREATE INDEX intelligence_case ON intelligence_links(case_id,id DESC);
CREATE TRIGGER immutable_original
        BEFORE UPDATE OF source_ref,sha256,size,filename,ingestion_source,created_at ON analyses
        WHEN OLD.source_ref IS NOT NULL
        BEGIN SELECT RAISE(ABORT,'Original evidence is immutable'); END;
