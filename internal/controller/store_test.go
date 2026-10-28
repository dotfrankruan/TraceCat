package controller

import (
	"context"
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
