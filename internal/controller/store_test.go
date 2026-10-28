package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func testStore(t *testing.T, maxHistory int) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.db")
	store, err := OpenStore(path, maxHistory)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleJob(id string, created time.Time, status model.JobStatus) *model.Job {
	return &model.Job{
		SchemaVersion:  model.ControllerSchemaVersion,
		ID:             id,
		Status:         status,
		TargetIP:       "8.8.8.8",
		OriginalTarget: "dns.example",
		Family:         model.FamilyIPv4,
		Protocol:       model.ProtocolICMP,
		MaxHops:        30,
		Queries:        3,
		TimeoutMS:      60000,
		CreatedAt:      created.UTC().Format(time.RFC3339Nano),
		CreatedBy:      "ops@example.com",
		Nodes: []model.NodeResult{
			{
				NodeID:   "tokyo-1",
				NodeName: "Tokyo",
				Status:   model.NodeCompleted,
				Hops: []model.Hop{{
					TTL: 1,
					Probes: []model.Probe{{
						Success: true,
						Address: "10.200.0.1",
					}},
				}},
			},
		},
		Summary: model.JobSummary{Total: 1, Completed: 1, Reached: 1},
	}
}

func TestStoreJobRoundTrip(t *testing.T) {
	store := testStore(t, 10)
	ctx := context.Background()
	now := time.Now().UTC()
	job := sampleJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now, model.JobRunning)

	raw := map[string]json.RawMessage{"tokyo-1": json.RawMessage(`{"Hops":[]}`)}
	if err := store.SaveJob(ctx, job, raw); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}

	got, err := store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.ID != job.ID || got.Status != model.JobRunning || got.TargetIP != "8.8.8.8" {
		t.Fatalf("unexpected job: %+v", got)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].NodeID != "tokyo-1" || len(got.Nodes[0].Hops) != 1 {
		t.Fatalf("unexpected nodes: %+v", got.Nodes)
	}

	raws, err := store.GetRawResults(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetRawResults: %v", err)
	}
	if string(raws["tokyo-1"]) != `{"Hops":[]}` {
		t.Fatalf("unexpected raw: %s", raws["tokyo-1"])
	}

	// Update: node moves to completed, raw results must be retained when the
	// incremental update has no new raw payload.
	job.Status = model.JobCompleted
	job.Nodes[0].Status = model.NodeCompleted
	if err := store.SaveJob(ctx, job, nil); err != nil {
		t.Fatalf("SaveJob update: %v", err)
	}
	got, err = store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJob after update: %v", err)
	}
	if got.Status != model.JobCompleted {
		t.Fatalf("status not updated: %q", got.Status)
	}
	raws, err = store.GetRawResults(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetRawResults after update: %v", err)
	}
	if _, ok := raws["tokyo-1"]; !ok {
		t.Fatalf("raw result was lost on update")
	}

	if _, err := store.GetJob(ctx, "dddddddddddddddddddddddddddddddd"); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("expected ErrStoreNotFound, got %v", err)
	}
}

func TestStoreListAndTrim(t *testing.T) {
	store := testStore(t, 2)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 4; i++ {
		job := sampleJob([]string{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04",
		}[i], base.Add(time.Duration(i)*time.Minute), model.JobCompleted)
		if err := store.SaveJob(ctx, job, nil); err != nil {
			t.Fatalf("SaveJob %d: %v", i, err)
		}
	}

	list, err := store.ListJobs(ctx, 20)
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(list))
	}
	if list[0].ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04" || list[1].ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03" {
		t.Fatalf("unexpected order: %v, %v", list[0].ID, list[1].ID)
	}
	if _, err := store.GetJob(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01"); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("oldest job should have been trimmed, got %v", err)
	}
}

func TestStoreSessions(t *testing.T) {
	store := testStore(t, 10)
	ctx := context.Background()
	now := time.Now().UTC()
	sess := SessionRecord{
		TokenHash: "hash-1",
		Subject:   "local",
		Email:     "ops@example.com",
		CSRFToken: "csrf",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := store.GetSession(ctx, "hash-1", now)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Subject != "local" || got.CSRFToken != "csrf" {
		t.Fatalf("unexpected session: %+v", got)
	}
	if _, err := store.GetSession(ctx, "hash-1", now.Add(2*time.Hour)); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("expected expired session to be gone, got %v", err)
	}
	if _, err := store.GetSession(ctx, "hash-1", now); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("expired session should have been deleted, got %v", err)
	}

	expired := sess
	expired.TokenHash = "hash-2"
	expired.ExpiresAt = now.Add(-time.Minute)
	live := sess
	live.TokenHash = "hash-3"
	if err := store.CreateSession(ctx, expired); err != nil {
		t.Fatalf("CreateSession expired: %v", err)
	}
	if err := store.CreateSession(ctx, live); err != nil {
		t.Fatalf("CreateSession live: %v", err)
	}
	n, err := store.DeleteExpiredSessions(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired session deleted, got %d", n)
	}

	if err := store.DeleteSession(ctx, "hash-3"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if err := store.DeleteSession(ctx, "hash-3"); err != nil {
		t.Fatalf("DeleteSession should be idempotent: %v", err)
	}
	if _, err := store.GetSession(ctx, "hash-3", now); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("session should be revoked, got %v", err)
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	store := testStore(t, 50)
	ctx := context.Background()
	const workers = 8
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "cccccccccccccccccccccccccccccc" + string(rune('a'+i))
			job := sampleJob(id, time.Now().UTC().Add(time.Duration(i)*time.Second), model.JobRunning)
			if err := store.SaveJob(ctx, job, nil); err != nil {
				t.Errorf("SaveJob: %v", err)
				return
			}
			if _, err := store.GetJob(ctx, id); err != nil {
				t.Errorf("GetJob: %v", err)
			}
			if _, err := store.ListJobs(ctx, 10); err != nil {
				t.Errorf("ListJobs: %v", err)
			}
			if err := store.CreateSession(ctx, SessionRecord{
				TokenHash: "h" + id,
				Subject:   "local",
				CSRFToken: "csrf",
				CreatedAt: time.Now().UTC(),
				ExpiresAt: time.Now().UTC().Add(time.Hour),
			}); err != nil {
				t.Errorf("CreateSession: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestStoreCorruptDatabaseFailsCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(path, []byte("this is not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path, 10)
	if err == nil {
		store.Close()
		t.Fatal("expected an error for a corrupt database")
	}
}

func TestStoreMemoryDatabase(t *testing.T) {
	store, err := OpenStore(":memory:", 5)
	if err != nil {
		t.Fatalf("OpenStore(:memory:): %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	job := sampleJob("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", time.Now().UTC(), model.JobPending)
	if err := store.SaveJob(ctx, job, nil); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}
	if _, err := store.GetJob(ctx, job.ID); err != nil {
		t.Fatalf("GetJob: %v", err)
	}
}

func TestStoreMarkInterruptedJobs(t *testing.T) {
	store := testStore(t, 10)
	ctx := context.Background()
	now := time.Now().UTC()

	interrupted := sampleJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", now, model.JobRunning)
	interrupted.StartedAt = now.Format(time.RFC3339Nano)
	interrupted.Nodes[0].Status = model.NodeRunning
	interrupted.Nodes = append(interrupted.Nodes, model.NodeResult{
		NodeID: "pending-node", NodeName: "Pending", Status: model.NodePending,
	})
	interrupted.Summary = model.SummarizeJob(interrupted.Nodes)
	if err := store.SaveJob(ctx, interrupted, nil); err != nil {
		t.Fatalf("SaveJob running: %v", err)
	}
	finished := sampleJob("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2", now, model.JobCompleted)
	finished.EndedAt = now.Format(time.RFC3339Nano)
	if err := store.SaveJob(ctx, finished, nil); err != nil {
		t.Fatalf("SaveJob completed: %v", err)
	}

	marked, err := store.MarkInterruptedJobs(ctx)
	if err != nil {
		t.Fatalf("MarkInterruptedJobs: %v", err)
	}
	if marked != 1 {
		t.Fatalf("marked = %d, want 1", marked)
	}
	loaded, err := store.GetJob(ctx, interrupted.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if loaded.Status != model.JobFailed {
		t.Fatalf("job status = %s, want failed", loaded.Status)
	}
	if loaded.EndedAt == "" {
		t.Fatal("interrupted job must get an ended_at timestamp")
	}
	for _, node := range loaded.Nodes {
		if node.Status != model.NodeFailed {
			t.Errorf("node %s status = %s, want failed", node.NodeID, node.Status)
		}
		if node.Error == nil || node.Error.Code != model.ErrInternal {
			t.Errorf("node %s error = %+v, want internal", node.NodeID, node.Error)
		}
	}
	if loaded.Summary.Failed != 2 {
		t.Errorf("summary failed = %d, want 2", loaded.Summary.Failed)
	}

	done, err := store.GetJob(ctx, finished.ID)
	if err != nil {
		t.Fatalf("GetJob completed: %v", err)
	}
	if done.Status != model.JobCompleted {
		t.Fatalf("terminal job was modified: status = %s", done.Status)
	}

	again, err := store.MarkInterruptedJobs(ctx)
	if err != nil || again != 0 {
		t.Fatalf("second MarkInterruptedJobs = %d, %v; want 0, nil", again, err)
	}
}

func intPtr(v int) *int { return &v }

func TestStoreJobProtocolAndPort(t *testing.T) {
	store := testStore(t, 10)
	ctx := context.Background()
	now := time.Now().UTC()

	tcpJob := sampleJob("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1", now, model.JobCompleted)
	tcpJob.Protocol = model.ProtocolTCP
	tcpJob.Port = intPtr(443)
	if err := store.SaveJob(ctx, tcpJob, nil); err != nil {
		t.Fatalf("SaveJob tcp: %v", err)
	}
	udpJob := sampleJob("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee2", now.Add(time.Second), model.JobCompleted)
	udpJob.Protocol = model.ProtocolUDP
	udpJob.Port = intPtr(model.DefaultUDPPort)
	if err := store.SaveJob(ctx, udpJob, nil); err != nil {
		t.Fatalf("SaveJob udp: %v", err)
	}
	icmpJob := sampleJob("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee3", now.Add(2*time.Second), model.JobCompleted)
	if err := store.SaveJob(ctx, icmpJob, nil); err != nil {
		t.Fatalf("SaveJob icmp: %v", err)
	}

	gotTCP, err := store.GetJob(ctx, tcpJob.ID)
	if err != nil {
		t.Fatalf("GetJob tcp: %v", err)
	}
	if gotTCP.Protocol != model.ProtocolTCP || gotTCP.Port == nil || *gotTCP.Port != 443 {
		t.Fatalf("tcp job protocol/port not persisted: %+v", gotTCP)
	}
	gotICMP, err := store.GetJob(ctx, icmpJob.ID)
	if err != nil {
		t.Fatalf("GetJob icmp: %v", err)
	}
	if gotICMP.Protocol != model.ProtocolICMP || gotICMP.Port != nil {
		t.Fatalf("icmp job must not carry a port: %+v", gotICMP)
	}

	list, err := store.ListJobs(ctx, 10)
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("list length = %d", len(list))
	}
	// Newest first: icmp, udp, tcp.
	if list[0].Protocol != model.ProtocolICMP || list[0].Port != nil {
		t.Fatalf("newest list item = %+v", list[0])
	}
	if list[1].Protocol != model.ProtocolUDP || list[1].Port == nil || *list[1].Port != model.DefaultUDPPort {
		t.Fatalf("udp list item = %+v", list[1])
	}
	if list[2].Protocol != model.ProtocolTCP || list[2].Port == nil || *list[2].Port != 443 {
		t.Fatalf("tcp list item = %+v", list[2])
	}
}

const legacySchemaSQL = `
CREATE TABLE jobs (
    id              TEXT PRIMARY KEY,
    created_unix    INTEGER NOT NULL,
    status          TEXT NOT NULL,
    target_ip       TEXT NOT NULL,
    original_target TEXT NOT NULL,
    family          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    ended_at        TEXT NOT NULL DEFAULT '',
    summary_json    TEXT NOT NULL,
    job_json        TEXT NOT NULL
);
CREATE TABLE job_nodes (
    job_id     TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    node_json  TEXT NOT NULL,
    raw_result TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (job_id, node_id)
);
CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    subject      TEXT NOT NULL,
    email        TEXT NOT NULL DEFAULT '',
    csrf_token   TEXT NOT NULL,
    created_unix INTEGER NOT NULL,
    expires_unix INTEGER NOT NULL
);
`

func TestStoreMigratesLegacyJobsWithoutProtocolColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	dsn, err := sqliteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(legacySchemaSQL); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	created := time.Now().UTC().Add(-time.Hour)
	legacy := sampleJob("fffffffffffffffffffffffffffffff1", created, model.JobCompleted)
	jobJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	summaryJSON, err := json.Marshal(legacy.Summary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
INSERT INTO jobs (id, created_unix, status, target_ip, original_target, family, created_at, ended_at, summary_json, job_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		legacy.ID, created.UnixNano(), string(legacy.Status), legacy.TargetIP, legacy.OriginalTarget,
		string(legacy.Family), legacy.CreatedAt, legacy.EndedAt, string(summaryJSON), string(jobJSON)); err != nil {
		t.Fatalf("insert legacy job: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(path, 10)
	if err != nil {
		t.Fatalf("OpenStore legacy: %v", err)
	}
	defer store.Close()

	// Columns were added in place.
	rows, err := store.db.Query(`PRAGMA table_info(jobs)`)
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{}
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
			t.Fatal(err)
		}
		columns[name] = true
	}
	rows.Close()
	if !columns["protocol"] || !columns["port"] {
		t.Fatalf("migration did not add columns: %v", columns)
	}

	ctx := context.Background()
	list, err := store.ListJobs(ctx, 10)
	if err != nil {
		t.Fatalf("ListJobs legacy: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("legacy list length = %d", len(list))
	}
	if list[0].Protocol != model.ProtocolICMP {
		t.Fatalf("legacy protocol was not backfilled: %+v", list[0])
	}
	if list[0].Port != nil {
		t.Fatalf("legacy icmp row must not have a port: %+v", list[0])
	}

	// New rows work normally after the in-place migration.
	tcpJob := sampleJob("fffffffffffffffffffffffffffffff2", time.Now().UTC(), model.JobCompleted)
	tcpJob.Protocol = model.ProtocolTCP
	tcpJob.Port = intPtr(8443)
	if err := store.SaveJob(ctx, tcpJob, nil); err != nil {
		t.Fatalf("SaveJob after migration: %v", err)
	}
	list, err = store.ListJobs(ctx, 10)
	if err != nil {
		t.Fatalf("ListJobs after migration: %v", err)
	}
	if len(list) != 2 || list[0].Protocol != model.ProtocolTCP || list[0].Port == nil || *list[0].Port != 8443 {
		t.Fatalf("new tcp row not listed first: %+v", list)
	}
}
