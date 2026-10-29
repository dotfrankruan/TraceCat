package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"

	_ "modernc.org/sqlite"
)

// ErrStoreNotFound is returned when a requested row does not exist (or an
// expired session was purged).
var ErrStoreNotFound = errors.New("store: not found")

// Store is the SQLite-backed persistence layer for jobs, per-node results,
// bounded raw NextTrace output and local-auth sessions. All statements are
// parameterized; the pool is deliberately limited to a single connection so
// SQLite's single-writer semantics are simple and race-free.
type Store struct {
	db         *sql.DB
	maxHistory int
	now        func() time.Time
}

// OpenStore opens (and migrates) the Controller database. A missing database
// file is created; a corrupt or inaccessible database is reported as a startup
// error instead of being silently replaced.
func OpenStore(path string, maxHistoryJobs int) (*Store, error) {
	path = filepath.Clean(path)
	if maxHistoryJobs < 1 {
		return nil, fmt.Errorf("store: max history jobs must be positive")
	}
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: prepare database directory: %w", err)
		}
	}
	dsn, err := sqliteDSN(path)
	if err != nil {
		return nil, fmt.Errorf("store: build database DSN: %w", err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, maxHistory: maxHistoryJobs, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: database is not usable: %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate database: %w", err)
	}
	if path != ":memory:" {
		// Auto-enrolled Agents' per-node trace tokens are stored in this
		// database because the Controller must present them when calling the
		// Agent. The directory is 0700; tighten the file too.
		if err := os.Chmod(path, 0o600); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: restrict database permissions: %w", err)
		}
	}
	return s, nil
}

func sqliteDSN(path string) (string, error) {
	// busy_timeout and foreign_keys are per-connection settings; modernc
	// applies _pragma parameters on every new connection. MaxOpenConns(1)
	// keeps the pool single-connection, so WAL and the pragmas are stable.
	params := url.Values{}
	params.Add("_pragma", "busy_timeout(5000)")
	params.Add("_pragma", "journal_mode(WAL)")
	params.Add("_pragma", "foreign_keys(1)")
	params.Add("_pragma", "synchronous(NORMAL)")
	if path == ":memory:" {
		return "file::memory:?" + params.Encode(), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: params.Encode()}
	return u.String(), nil
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    created_unix    INTEGER NOT NULL,
    status          TEXT NOT NULL,
    target_ip       TEXT NOT NULL,
    original_target TEXT NOT NULL,
    family          TEXT NOT NULL,
    protocol        TEXT NOT NULL DEFAULT '',
    port            INTEGER,
    created_at      TEXT NOT NULL,
    ended_at        TEXT NOT NULL DEFAULT '',
    summary_json    TEXT NOT NULL,
    job_json        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_created_idx ON jobs (created_unix DESC);

CREATE TABLE IF NOT EXISTS job_nodes (
    job_id     TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    node_id    TEXT NOT NULL,
    node_json  TEXT NOT NULL,
    raw_result TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (job_id, node_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash   TEXT PRIMARY KEY,
    subject      TEXT NOT NULL,
    email        TEXT NOT NULL DEFAULT '',
    csrf_token   TEXT NOT NULL,
    created_unix INTEGER NOT NULL,
    expires_unix INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_unix);

CREATE TABLE IF NOT EXISTS registered_agents (
    node_id          TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    location         TEXT NOT NULL DEFAULT '',
    provider         TEXT NOT NULL DEFAULT '',
    url              TEXT NOT NULL,
    agent_token      TEXT NOT NULL,
    protocols        TEXT NOT NULL DEFAULT '[]',
    nexttrace_version TEXT NOT NULL DEFAULT '',
    created_unix     INTEGER NOT NULL,
    updated_unix     INTEGER NOT NULL,
    last_seen_unix   INTEGER NOT NULL DEFAULT 0
);
`

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}
	// Databases created before TCP/UDP support lack the protocol/port list
	// columns. Add them in place and backfill from the full job JSON so
	// upgraded deployments keep honest history. The backfill is idempotent and
	// runs unconditionally, which also repairs a migration interrupted between
	// the ALTER and the UPDATE.
	if _, _, err := s.ensureJobColumns(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
UPDATE jobs SET protocol = LOWER(COALESCE(json_extract(job_json, '$.protocol'), ''))
WHERE protocol = ''`); err != nil {
		return fmt.Errorf("store: backfill job protocol: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
UPDATE jobs SET port = CAST(json_extract(job_json, '$.port') AS INTEGER)
WHERE port IS NULL AND json_extract(job_json, '$.port') IS NOT NULL`); err != nil {
		return fmt.Errorf("store: backfill job port: %w", err)
	}
	return nil
}

// ensureJobColumns adds the protocol/port history columns to databases created
// by earlier releases. It reports which columns were added so callers can
// backfill exactly once.
func (s *Store) ensureJobColumns(ctx context.Context) (protocolAdded, portAdded bool, err error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(jobs)`)
	if err != nil {
		return false, false, fmt.Errorf("store: inspect job schema: %w", err)
	}
	columns := make(map[string]struct{}, 12)
	for rows.Next() {
		var (
			cid          int
			name         string
			columnType   string
			notNull      int
			defaultValue any
			primaryKey   int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return false, false, fmt.Errorf("store: inspect job schema: %w", err)
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, false, fmt.Errorf("store: inspect job schema: %w", err)
	}
	rows.Close()

	if _, ok := columns["protocol"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE jobs ADD COLUMN protocol TEXT NOT NULL DEFAULT ''`); err != nil {
			return false, false, fmt.Errorf("store: add job protocol column: %w", err)
		}
		protocolAdded = true
	}
	if _, ok := columns["port"]; !ok {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE jobs ADD COLUMN port INTEGER`); err != nil {
			return false, false, fmt.Errorf("store: add job port column: %w", err)
		}
		portAdded = true
	}
	return protocolAdded, portAdded, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// SaveJob upserts the full job document, its per-node results and any raw
// results, then trims the history to the newest maxHistory jobs. Raw results
// are expected to be pre-bounded by the job manager.
func (s *Store) SaveJob(ctx context.Context, job *model.Job, raw map[string]json.RawMessage) error {
	if job == nil || job.ID == "" {
		return fmt.Errorf("store: job is missing an id")
	}
	jobJSON, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("store: encode job: %w", err)
	}
	summaryJSON, err := json.Marshal(job.Summary)
	if err != nil {
		return fmt.Errorf("store: encode summary: %w", err)
	}
	createdUnix := parseRFC3339Unix(job.CreatedAt, s.now())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var portValue any
	if job.Port != nil {
		portValue = *job.Port
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO jobs (id, created_unix, status, target_ip, original_target, family, protocol, port, created_at, ended_at, summary_json, job_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    status = excluded.status,
    protocol = excluded.protocol,
    port = excluded.port,
    ended_at = excluded.ended_at,
    summary_json = excluded.summary_json,
    job_json = excluded.job_json`,
		job.ID, createdUnix, string(job.Status), job.TargetIP, job.OriginalTarget, string(job.Family),
		string(job.Protocol), portValue, job.CreatedAt, job.EndedAt, string(summaryJSON), string(jobJSON)); err != nil {
		return fmt.Errorf("store: save job: %w", err)
	}

	for i := range job.Nodes {
		node := &job.Nodes[i]
		nodeJSON, err := json.Marshal(node)
		if err != nil {
			return fmt.Errorf("store: encode node result: %w", err)
		}
		rawJSON := ""
		if raw != nil {
			if r, ok := raw[node.NodeID]; ok && len(r) > 0 {
				rawJSON = string(r)
			}
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO job_nodes (job_id, node_id, node_json, raw_result)
VALUES (?, ?, ?, ?)
ON CONFLICT(job_id, node_id) DO UPDATE SET
    node_json = excluded.node_json,
    raw_result = CASE WHEN excluded.raw_result <> '' THEN excluded.raw_result ELSE job_nodes.raw_result END`,
			job.ID, node.NodeID, string(nodeJSON), rawJSON); err != nil {
			return fmt.Errorf("store: save job node: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
DELETE FROM jobs WHERE id NOT IN (
    SELECT id FROM jobs ORDER BY created_unix DESC, rowid DESC LIMIT ?
)`, s.maxHistory); err != nil {
		return fmt.Errorf("store: trim job history: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit job: %w", err)
	}
	return nil
}

// MarkInterruptedJobs reconciles jobs left in a non-terminal state by a
// previous Controller process. Trace jobs are not resumed after a restart, so
// such jobs (and their still-pending/running nodes) are marked failed with a
// safe normalized error instead of being reported as "running" forever. It is
// called once at startup; terminal jobs are never modified.
func (s *Store) MarkInterruptedJobs(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, job_json FROM jobs WHERE status IN (?, ?)`,
		string(model.JobPending), string(model.JobRunning))
	if err != nil {
		return 0, fmt.Errorf("store: list interrupted jobs: %w", err)
	}
	type interrupted struct {
		id  string
		job model.Job
	}
	var found []interrupted
	for rows.Next() {
		var id, jobJSON string
		if err := rows.Scan(&id, &jobJSON); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("store: scan interrupted job: %w", err)
		}
		var job model.Job
		if err := json.Unmarshal([]byte(jobJSON), &job); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("store: decode interrupted job: %w", err)
		}
		found = append(found, interrupted{id: id, job: job})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("store: iterate interrupted jobs: %w", err)
	}
	_ = rows.Close()

	now := s.now().UTC().Format(time.RFC3339Nano)
	marked := 0
	for _, item := range found {
		job := item.job
		if job.Status != model.JobPending && job.Status != model.JobRunning {
			continue // already terminal; leave untouched
		}
		job.Status = model.JobFailed
		job.EndedAt = now
		for i := range job.Nodes {
			if job.Nodes[i].Status.Terminal() {
				continue
			}
			job.Nodes[i].Status = model.NodeFailed
			job.Nodes[i].EndedAt = now
			job.Nodes[i].Error = model.NewError(model.ErrInternal,
				"controller restarted before this trace completed")
		}
		job.Summary = model.SummarizeJob(job.Nodes)
		if err := s.SaveJob(ctx, &job, nil); err != nil {
			return marked, fmt.Errorf("store: mark interrupted job %s: %w", item.id, err)
		}
		marked++
	}
	return marked, nil
}

// GetJob returns the full job document. Raw results are fetched separately by
// GetRawResults.
func (s *Store) GetJob(ctx context.Context, id string) (*model.Job, error) {
	var jobJSON string
	err := s.db.QueryRowContext(ctx, `SELECT job_json FROM jobs WHERE id = ?`, id).Scan(&jobJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStoreNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get job: %w", err)
	}
	var job model.Job
	if err := json.Unmarshal([]byte(jobJSON), &job); err != nil {
		return nil, fmt.Errorf("store: decode job: %w", err)
	}
	return &job, nil
}

// GetRawResults returns the bounded raw NextTrace results for a job, keyed by
// node id.
func (s *Store) GetRawResults(ctx context.Context, id string) (map[string]json.RawMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, raw_result FROM job_nodes WHERE job_id = ? AND raw_result <> ''`, id)
	if err != nil {
		return nil, fmt.Errorf("store: get raw results: %w", err)
	}
	defer rows.Close()
	out := make(map[string]json.RawMessage)
	for rows.Next() {
		var nodeID, raw string
		if err := rows.Scan(&nodeID, &raw); err != nil {
			return nil, fmt.Errorf("store: scan raw result: %w", err)
		}
		if json.Valid([]byte(raw)) {
			out[nodeID] = json.RawMessage(raw)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate raw results: %w", err)
	}
	return out, nil
}

// ListJobs returns recent history, newest first, without hops.
func (s *Store) ListJobs(ctx context.Context, limit int) ([]model.JobListItem, error) {
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if limit > s.maxHistory {
		limit = s.maxHistory
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, status, target_ip, original_target, family, protocol, port, created_at, ended_at, summary_json
FROM jobs ORDER BY created_unix DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list jobs: %w", err)
	}
	defer rows.Close()

	items := make([]model.JobListItem, 0, limit)
	for rows.Next() {
		var (
			item        model.JobListItem
			status      string
			family      string
			protocol    string
			port        sql.NullInt64
			summaryJSON string
		)
		if err := rows.Scan(&item.ID, &status, &item.TargetIP, &item.OriginalTarget, &family,
			&protocol, &port, &item.CreatedAt, &item.EndedAt, &summaryJSON); err != nil {
			return nil, fmt.Errorf("store: scan job list: %w", err)
		}
		item.Status = model.JobStatus(status)
		item.Family = model.IPFamily(family)
		item.Protocol = model.Protocol(protocol)
		if port.Valid {
			portValue := int(port.Int64)
			item.Port = &portValue
		}
		if err := json.Unmarshal([]byte(summaryJSON), &item.Summary); err != nil {
			return nil, fmt.Errorf("store: decode job summary: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate jobs: %w", err)
	}
	return items, nil
}

func parseRFC3339Unix(value string, fallback time.Time) int64 {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return fallback.UTC().UnixNano()
	}
	return t.UTC().UnixNano()
}

// SessionRecord is one server-side local-auth session. Only the SHA-256 hash of
// the cookie token is stored.
type SessionRecord struct {
	TokenHash string
	Subject   string
	Email     string
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateSession stores a new local-auth session.
func (s *Store) CreateSession(ctx context.Context, sess SessionRecord) error {
	if sess.TokenHash == "" || sess.CSRFToken == "" || sess.Subject == "" {
		return fmt.Errorf("store: incomplete session record")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sessions (token_hash, subject, email, csrf_token, created_unix, expires_unix)
VALUES (?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.Subject, sess.Email, sess.CSRFToken,
		sess.CreatedAt.UTC().UnixNano(), sess.ExpiresAt.UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession returns a live session by token hash. Expired sessions are
// deleted and reported as not found.
func (s *Store) GetSession(ctx context.Context, tokenHash string, now time.Time) (*SessionRecord, error) {
	var (
		sess        SessionRecord
		createdNano int64
		expiresNano int64
	)
	err := s.db.QueryRowContext(ctx, `
SELECT token_hash, subject, email, csrf_token, created_unix, expires_unix
FROM sessions WHERE token_hash = ?`, tokenHash).
		Scan(&sess.TokenHash, &sess.Subject, &sess.Email, &sess.CSRFToken, &createdNano, &expiresNano)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStoreNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get session: %w", err)
	}
	sess.CreatedAt = time.Unix(0, createdNano).UTC()
	sess.ExpiresAt = time.Unix(0, expiresNano).UTC()
	if !sess.ExpiresAt.After(now.UTC()) {
		_ = s.DeleteSession(ctx, tokenHash)
		return nil, ErrStoreNotFound
	}
	return &sess, nil
}

// DeleteSession revokes one session. Deleting an absent session is not an
// error (logout is idempotent).
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// DeleteExpiredSessions purges expired sessions and returns the count removed.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_unix <= ?`, now.UTC().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// RegisteredAgent is an Agent that enrolled itself through the secure
// enrollment endpoint. AgentToken is the per-Agent trace token the Controller
// must present on /v1/health and /v1/trace calls; it is stored in the protected
// Controller database (directory 0700, file 0600) because the Controller needs
// the raw value, unlike local browser sessions which store only hashes.
type RegisteredAgent struct {
	NodeID           string
	Name             string
	Location         string
	Provider         string
	URL              string
	AgentToken       string
	Protocols        []string
	NextTraceVersion string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	LastSeenAt       time.Time
}

// UpsertRegisteredAgent creates or updates an auto-enrolled Agent. The original
// creation timestamp is preserved across re-enrollment/token rotation.
func (s *Store) UpsertRegisteredAgent(ctx context.Context, agent RegisteredAgent) error {
	if agent.NodeID == "" || agent.URL == "" || agent.AgentToken == "" {
		return fmt.Errorf("store: incomplete registered agent record")
	}
	now := s.now().UTC()
	created := agent.CreatedAt.UTC()
	if created.IsZero() {
		created = now
	}
	updated := agent.UpdatedAt.UTC()
	if updated.IsZero() {
		updated = now
	}
	lastSeen := agent.LastSeenAt.UTC().UnixNano()
	protocols, err := json.Marshal(agent.Protocols)
	if err != nil {
		return fmt.Errorf("store: encode registered agent protocols: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO registered_agents
    (node_id, name, location, provider, url, agent_token, protocols, nexttrace_version, created_unix, updated_unix, last_seen_unix)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(node_id) DO UPDATE SET
    name = excluded.name,
    location = excluded.location,
    provider = excluded.provider,
    url = excluded.url,
    agent_token = excluded.agent_token,
    protocols = excluded.protocols,
    nexttrace_version = excluded.nexttrace_version,
    updated_unix = excluded.updated_unix,
    last_seen_unix = excluded.last_seen_unix`,
		agent.NodeID, agent.Name, agent.Location, agent.Provider, agent.URL, agent.AgentToken,
		string(protocols), agent.NextTraceVersion, created.UnixNano(), updated.UnixNano(), lastSeen); err != nil {
		return fmt.Errorf("store: upsert registered agent: %w", err)
	}
	return nil
}

// ListRegisteredAgents returns all auto-enrolled Agents in creation order.
func (s *Store) ListRegisteredAgents(ctx context.Context) ([]RegisteredAgent, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT node_id, name, location, provider, url, agent_token, protocols, nexttrace_version, created_unix, updated_unix, last_seen_unix
FROM registered_agents ORDER BY created_unix ASC, node_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list registered agents: %w", err)
	}
	defer rows.Close()
	out := make([]RegisteredAgent, 0)
	for rows.Next() {
		agent, err := scanRegisteredAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate registered agents: %w", err)
	}
	return out, nil
}

// GetRegisteredAgent returns one auto-enrolled Agent.
func (s *Store) GetRegisteredAgent(ctx context.Context, nodeID string) (*RegisteredAgent, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT node_id, name, location, provider, url, agent_token, protocols, nexttrace_version, created_unix, updated_unix, last_seen_unix
FROM registered_agents WHERE node_id = ?`, nodeID)
	agent, err := scanRegisteredAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStoreNotFound
	}
	if err != nil {
		return nil, err
	}
	return &agent, nil
}

// TouchRegisteredAgentLastSeen records a successful health check for an
// auto-enrolled Agent.
func (s *Store) TouchRegisteredAgentLastSeen(ctx context.Context, nodeID string, at time.Time) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE registered_agents SET last_seen_unix = ? WHERE node_id = ?`,
		at.UTC().UnixNano(), nodeID); err != nil {
		return fmt.Errorf("store: touch registered agent: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRegisteredAgent(row rowScanner) (RegisteredAgent, error) {
	var (
		agent                    RegisteredAgent
		protocols                string
		createdUnix, updatedUnix int64
		lastSeenUnix             int64
	)
	if err := row.Scan(&agent.NodeID, &agent.Name, &agent.Location, &agent.Provider, &agent.URL,
		&agent.AgentToken, &protocols, &agent.NextTraceVersion,
		&createdUnix, &updatedUnix, &lastSeenUnix); err != nil {
		return RegisteredAgent{}, err
	}
	if protocols != "" {
		if err := json.Unmarshal([]byte(protocols), &agent.Protocols); err != nil {
			return RegisteredAgent{}, fmt.Errorf("store: decode registered agent protocols: %w", err)
		}
	}
	agent.CreatedAt = time.Unix(0, createdUnix).UTC()
	agent.UpdatedAt = time.Unix(0, updatedUnix).UTC()
	if lastSeenUnix > 0 {
		agent.LastSeenAt = time.Unix(0, lastSeenUnix).UTC()
	}
	return agent, nil
}
