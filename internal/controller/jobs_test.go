package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func boolPtr(v bool) *bool { return &v }

func TestEndToEndFakeAgentJob(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a2 := newFakeAgent(t, "node-two")
	h := newHarness(t, withAgents(a1, a2))

	// Health checks feed GET /api/v1/nodes.
	h.registry.CheckAll(context.Background())

	resp, body := h.get("/api/v1/nodes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nodes status = %d body=%s", resp.StatusCode, body)
	}
	nodes := decodeJSONResponse[model.NodeList](t, resp, body)
	if len(nodes.Nodes) != 2 || nodes.Nodes[0].ID != "node-one" || nodes.Nodes[0].Health != HealthOK {
		t.Fatalf("unexpected node list: %+v", nodes.Nodes)
	}
	if nodes.Nodes[0].LastSeen == "" || nodes.Nodes[0].NextTraceVersion != "v1.7.3" {
		t.Fatalf("health metadata missing: %+v", nodes.Nodes[0])
	}

	// Central resolution.
	resp, body = h.post("/api/v1/resolve", model.ResolveRequest{Target: "dns.example"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve status = %d body=%s", resp.StatusCode, body)
	}
	resolved := decodeJSONResponse[model.ResolveResponse](t, resp, body)
	if len(resolved.Addresses) != 2 || !resolved.RequiresSelection || resolved.Kind != "domain" {
		t.Fatalf("unexpected resolve response: %+v", resolved)
	}

	// Full distributed job.
	resp, body = h.createJob(model.CreateJobRequest{
		TargetIP:       "8.8.8.8",
		OriginalTarget: "dns.example",
		NodeIDs:        []string{"node-one", "node-two"},
		Protocol:       model.ProtocolICMP,
		MaxHops:        30,
		Queries:        3,
		TimeoutMS:      60000,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	created := decodeJSONResponse[model.JobResponse](t, resp, body).Job
	if created.ID == "" || created.Status != model.JobPending {
		t.Fatalf("unexpected created job: %+v", created)
	}
	if len(created.Nodes) != 2 || created.Nodes[0].Status != model.NodePending {
		t.Fatalf("unexpected initial nodes: %+v", created.Nodes)
	}
	if created.CreatedBy == "" {
		t.Fatalf("created_by should be set in dev mode")
	}

	final := waitForTerminalJob(t, h.manager, created.ID)
	if final.Status != model.JobCompleted {
		t.Fatalf("job status = %q, want completed (%+v)", final.Status, final.Summary)
	}
	if final.Summary.Completed != 2 || final.Summary.Total != 2 || final.Summary.Reached != 2 {
		t.Fatalf("unexpected summary: %+v", final.Summary)
	}
	for _, node := range final.Nodes {
		if node.Status != model.NodeCompleted || node.Summary == nil || !node.Summary.ReachedDestination {
			t.Fatalf("unexpected node result: %+v", node)
		}
		if node.DurationMS == nil || node.NextTraceVersion != "v1.7.3" {
			t.Fatalf("node metadata missing: %+v", node)
		}
		if len(node.Hops) != 2 || node.Hops[1].TTL != 2 {
			t.Fatalf("unexpected hops: %+v", node.Hops)
		}
	}

	// GET /api/v1/jobs/{id}
	resp, body = h.get("/api/v1/jobs/" + created.ID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get job status = %d body=%s", resp.StatusCode, body)
	}
	got := decodeJSONResponse[model.JobResponse](t, resp, body).Job
	if got.ID != created.ID || got.Status != model.JobCompleted {
		t.Fatalf("unexpected fetched job: %+v", got)
	}
	if got.CreatedAt == "" || got.StartedAt == "" || got.EndedAt == "" {
		t.Fatalf("timestamps missing: %+v", got)
	}

	// Export includes bounded raw results.
	resp, body = h.get("/api/v1/jobs/" + created.ID + "/export")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d body=%s", resp.StatusCode, body)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("export is not an attachment: %q", cd)
	}
	export := decodeJSONResponse[model.JobExport](t, resp, body)
	if string(export.RawResults["node-one"]) == "" || !strings.Contains(string(export.RawResults["node-one"]), "Hops") {
		t.Fatalf("export is missing raw results: %s", export.RawResults["node-one"])
	}
	if export.Job.ID != created.ID || export.SchemaVersion != model.ControllerSchemaVersion {
		t.Fatalf("unexpected export: %+v", export)
	}

	// History list has no hops.
	resp, body = h.get("/api/v1/jobs")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list jobs status = %d body=%s", resp.StatusCode, body)
	}
	list := decodeJSONResponse[model.JobList](t, resp, body)
	if len(list.Jobs) != 1 || list.Jobs[0].ID != created.ID {
		t.Fatalf("unexpected history: %+v", list.Jobs)
	}
	if a1.traceCount() != 1 || a2.traceCount() != 1 {
		t.Fatalf("agents should have been called once each")
	}
}

func TestJobPartialFailure(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a2 := newFakeAgent(t, "node-two")
	a2.setTraceHandler(func(w http.ResponseWriter, _ *http.Request, _ model.AgentTraceRequest) {
		writeTestJSONStatus(t, w, http.StatusInternalServerError, model.Err(model.ErrInternal, "boom"))
	})
	h := newHarness(t, withAgents(a1, a2))

	resp, body := h.createJob(model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one", "node-two"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Status != model.JobPartial {
		t.Fatalf("job status = %q, want partial", final.Status)
	}
	if final.Summary.Completed != 1 || final.Summary.Failed != 1 {
		t.Fatalf("unexpected summary: %+v", final.Summary)
	}
	for _, node := range final.Nodes {
		switch node.NodeID {
		case "node-one":
			if node.Status != model.NodeCompleted {
				t.Fatalf("node-one status = %q", node.Status)
			}
		case "node-two":
			if node.Status != model.NodeFailed {
				t.Fatalf("node-two status = %q", node.Status)
			}
			if node.Error == nil || node.Error.Code != model.ErrAgentUnreachable {
				t.Fatalf("unexpected node error: %+v", node.Error)
			}
		}
	}
}

func TestJobNodeTimeout(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setTraceHandler(func(_ http.ResponseWriter, r *http.Request, _ model.AgentTraceRequest) {
		<-r.Context().Done()
	})
	h := newHarness(t, withAgents(a1), withConfigMutation(func(cfg *Config) {
		// A tiny per-agent cap makes the test fast; production configs must
		// exceed the trace timeout.
		cfg.Agents[0].RequestTimeoutMS = 150
	}))

	resp, body := h.createJob(model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Status != model.JobFailed {
		t.Fatalf("job status = %q, want failed", final.Status)
	}
	node := final.Nodes[0]
	if node.Status != model.NodeTimedOut {
		t.Fatalf("node status = %q, want timed_out", node.Status)
	}
	if node.Error == nil || node.Error.Code != model.ErrTimeout {
		t.Fatalf("unexpected node error: %+v", node.Error)
	}
}

func TestJobCancellation(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setTraceHandler(func(_ http.ResponseWriter, r *http.Request, _ model.AgentTraceRequest) {
		<-r.Context().Done()
	})
	h := newHarness(t, withAgents(a1))

	resp, body := h.createJob(model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, apiErr := h.manager.GetJob(context.Background(), id)
		if apiErr != nil {
			t.Fatalf("GetJob: %v", apiErr)
		}
		if job.Status == model.JobRunning {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	resp, body = h.post("/api/v1/jobs/"+id+"/cancel", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel status = %d body=%s", resp.StatusCode, body)
	}
	final := waitForTerminalJob(t, h.manager, id)
	if final.Status != model.JobCancelled {
		t.Fatalf("job status = %q, want cancelled", final.Status)
	}
	if final.Nodes[0].Status != model.NodeCancelled {
		t.Fatalf("node status = %q, want cancelled", final.Nodes[0].Status)
	}

	// A terminal job cannot be cancelled again.
	resp, body = h.post("/api/v1/jobs/"+id+"/cancel", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second cancel status = %d body=%s", resp.StatusCode, body)
	}
	// Unknown job ids are 404.
	resp, _ = h.post("/api/v1/jobs/0123456789abcdef0123456789abcdef/cancel", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown cancel status = %d", resp.StatusCode)
	}
}

func TestJobMalformedAgentResponse(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setTraceHandler(func(w http.ResponseWriter, _ *http.Request, _ model.AgentTraceRequest) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json"))
	})
	h := newHarness(t, withAgents(a1))

	resp, body := h.createJob(model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Nodes[0].Status != model.NodeFailed {
		t.Fatalf("node status = %q, want failed", final.Nodes[0].Status)
	}
	if final.Nodes[0].Error == nil || final.Nodes[0].Error.Code != model.ErrParseError {
		t.Fatalf("unexpected node error: %+v", final.Nodes[0].Error)
	}
}

func TestJobOversizedAgentResponse(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setTraceHandler(func(w http.ResponseWriter, _ *http.Request, req model.AgentTraceRequest) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schema_version":"` + model.AgentSchemaVersion + `","padding":"`))
		_, _ = w.Write([]byte(strings.Repeat("a", 4096)))
		_, _ = w.Write([]byte(`"}`))
	})
	h := newHarness(t, withAgents(a1), withAgentClient(NewAgentClient(WithAgentMaxResponseBytes(1024))))

	resp, body := h.createJob(model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Nodes[0].Status != model.NodeFailed {
		t.Fatalf("node status = %q, want failed", final.Nodes[0].Status)
	}
	if final.Nodes[0].Error == nil || final.Nodes[0].Error.Code != ErrAgentError {
		t.Fatalf("unexpected node error: %+v", final.Nodes[0].Error)
	}
}

func TestJobUnknownAndDisabledNodes(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a2 := newFakeAgent(t, "node-two")
	h := newHarness(t, withAgents(a1, a2), withConfigMutation(func(cfg *Config) {
		cfg.Agents[1].Enabled = boolPtr(false)
	}))

	base := model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"ghost-node"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	}
	resp, body := h.createJob(base)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown node status = %d body=%s", resp.StatusCode, body)
	}

	disabled := base
	disabled.NodeIDs = []string{"node-two"}
	resp, body = h.createJob(disabled)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled node status = %d body=%s", resp.StatusCode, body)
	}
	if a2.traceCount() != 0 {
		t.Fatalf("disabled agent must never be called")
	}
}

func TestJobLimitsValidation(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1))

	base := model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	}
	cases := []struct {
		name string
		req  model.CreateJobRequest
	}{
		{"max hops", func() model.CreateJobRequest { r := base; r.MaxHops = 65; return r }()},
		{"queries zero", func() model.CreateJobRequest { r := base; r.Queries = 0; return r }()},
		{"timeout too small", func() model.CreateJobRequest { r := base; r.TimeoutMS = 1000; return r }()},
		{"protocol", func() model.CreateJobRequest { r := base; r.Protocol = "tcp"; return r }()},
		{"no nodes", func() model.CreateJobRequest { r := base; r.NodeIDs = nil; return r }()},
		{"duplicate nodes", func() model.CreateJobRequest {
			r := base
			r.NodeIDs = []string{"node-one", "node-one"}
			return r
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := h.createJob(tc.req)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", resp.StatusCode, body)
			}
		})
	}
}

func TestJobTargetRejected(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1))
	for _, target := range []string{"10.0.0.1", "127.0.0.1", "2001:db8::1", "not-an-ip"} {
		resp, body := h.createJob(model.CreateJobRequest{
			TargetIP: target, OriginalTarget: "x.example",
			NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
			MaxHops: 30, Queries: 3, TimeoutMS: 60000,
		})
		if resp.StatusCode != http.StatusUnprocessableEntity && resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("target %q status = %d body=%s", target, resp.StatusCode, body)
		}
	}
}

func TestJobBodyTooLarge(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1))
	resp, body := h.request(http.MethodPost, "/api/v1/jobs", strings.Repeat("a", 9000),
		map[string]string{csrfHeaderName: h.csrfToken()})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
}

func TestJobConcurrentLimit(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	release := make(chan struct{})
	a1.setTraceHandler(func(w http.ResponseWriter, r *http.Request, req model.AgentTraceRequest) {
		select {
		case <-release:
			writeTestJSON(t, w, completedTraceResponse(req))
		case <-r.Context().Done():
		}
	})
	h := newHarness(t, withAgents(a1), withConfigMutation(func(cfg *Config) {
		cfg.Limits.MaxConcurrentJobs = 1
	}))

	req := model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	}
	resp, body := h.createJob(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID

	resp, body = h.createJob(req)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second job status = %d body=%s", resp.StatusCode, body)
	}
	close(release)
	waitForTerminalJob(t, h.manager, id)

	// The slot is released again.
	resp, body = h.createJob(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("third job status = %d body=%s", resp.StatusCode, body)
	}
}

func TestJobRateLimit(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1), withConfigMutation(func(cfg *Config) {
		cfg.Limits.MaxJobsPerMinute = 1
	}))
	req := model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	}
	resp, body := h.createJob(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first job status = %d body=%s", resp.StatusCode, body)
	}
	resp, body = h.createJob(req)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second job status = %d body=%s", resp.StatusCode, body)
	}
}

func TestJobSSEStream(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setTraceHandler(func(w http.ResponseWriter, r *http.Request, req model.AgentTraceRequest) {
		select {
		case <-time.After(120 * time.Millisecond):
			writeTestJSON(t, w, completedTraceResponse(req))
		case <-r.Context().Done():
		}
	})
	h := newHarness(t, withAgents(a1), withAPIOptions(WithAPISSEHeartbeat(25*time.Millisecond)))

	resp, body := h.createJob(model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/jobs/"+id+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer stream.Body.Close()
	if got := stream.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("content type = %q", got)
	}

	var snapshots []model.Job
	pingSeen := false
	eventSeen := false
	scanner := bufio.NewScanner(stream.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ": ping") {
			pingSeen = true
			continue
		}
		if line == "event: job" {
			eventSeen = true
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			var job model.Job
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &job); err != nil {
				t.Fatalf("decode SSE payload: %v line=%q", err, line)
			}
			snapshots = append(snapshots, job)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan SSE: %v", err)
	}
	if !eventSeen || len(snapshots) < 2 {
		t.Fatalf("expected event:job frames, got event=%v snapshots=%d", eventSeen, len(snapshots))
	}
	if snapshots[0].ID != id {
		t.Fatalf("initial snapshot is for %q", snapshots[0].ID)
	}
	last := snapshots[len(snapshots)-1]
	if last.Status != model.JobCompleted {
		t.Fatalf("final snapshot status = %q", last.Status)
	}
	if !pingSeen {
		t.Fatalf("expected a heartbeat comment")
	}
}

func TestJobHistoryTrim(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1), withConfigMutation(func(cfg *Config) {
		cfg.Database.MaxHistoryJobs = 2
	}))
	req := model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{"node-one"}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	}
	for i := 0; i < 3; i++ {
		resp, body := h.createJob(req)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("job %d status = %d body=%s", i, resp.StatusCode, body)
		}
		waitForTerminalJob(t, h.manager, decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID)
	}

	resp, body := h.get("/api/v1/jobs")
	list := decodeJSONResponse[model.JobList](t, resp, body)
	if len(list.Jobs) != 2 {
		t.Fatalf("history length = %d, want 2", len(list.Jobs))
	}
	resp, body = h.get("/api/v1/jobs?limit=1")
	list = decodeJSONResponse[model.JobList](t, resp, body)
	if len(list.Jobs) != 1 {
		t.Fatalf("limit=1 returned %d jobs", len(list.Jobs))
	}
	resp, body = h.get("/api/v1/jobs?limit=bogus")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid limit status = %d body=%s", resp.StatusCode, body)
	}
}

func TestRegistryHealthPoller(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1))
	ctx, cancel := context.WithCancel(context.Background())
	h.registry.Start(ctx, 20*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.registry.Health("node-one") == HealthOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.registry.Health("node-one"); got != HealthOK {
		t.Fatalf("health = %q, want ok", got)
	}
	cancel()
	h.registry.Wait()

	// An unreachable agent degrades to unreachable.
	a1.srv.Close()
	h.registry.CheckAll(context.Background())
	if got := h.registry.Health("node-one"); got != HealthUnreachable {
		t.Fatalf("health after close = %q, want unreachable", got)
	}
}

func protocolJobRequest(protocol model.Protocol, port *int) model.CreateJobRequest {
	return model.CreateJobRequest{
		TargetIP:       "8.8.8.8",
		OriginalTarget: "dns.example",
		NodeIDs:        []string{"node-one"},
		Protocol:       protocol,
		Port:           port,
		MaxHops:        30,
		Queries:        3,
		TimeoutMS:      60000,
	}
}

func expectedAgentRequest(jobID string, protocol model.Protocol, port *int) model.AgentTraceRequest {
	return model.AgentTraceRequest{
		SchemaVersion: model.AgentSchemaVersion,
		JobID:         jobID,
		NodeID:        "node-one",
		TargetIP:      "8.8.8.8",
		Family:        model.FamilyIPv4,
		Protocol:      protocol,
		Port:          port,
		MaxHops:       30,
		Queries:       3,
		TimeoutMS:     60000,
	}
}

func TestJobTCPExactDispatchAndEcho(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1))

	port := 443
	resp, body := h.createJob(protocolJobRequest(model.ProtocolTCP, &port))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create tcp job status = %d body=%s", resp.StatusCode, body)
	}
	created := decodeJSONResponse[model.JobResponse](t, resp, body).Job
	if created.Protocol != model.ProtocolTCP || created.Port == nil || *created.Port != 443 {
		t.Fatalf("created job protocol/port = %s/%v", created.Protocol, created.Port)
	}
	final := waitForTerminalJob(t, h.manager, created.ID)
	if final.Status != model.JobCompleted {
		t.Fatalf("job status = %q", final.Status)
	}

	dispatched, rawBody := a1.lastTraceRequest()
	if dispatched.Protocol != model.ProtocolTCP || dispatched.Port == nil || *dispatched.Port != 443 {
		t.Fatalf("dispatched request protocol/port = %s/%v", dispatched.Protocol, dispatched.Port)
	}
	want, err := json.Marshal(expectedAgentRequest(created.ID, model.ProtocolTCP, &port))
	if err != nil {
		t.Fatal(err)
	}
	if string(rawBody) != string(want) {
		t.Fatalf("dispatched body mismatch:\n got: %s\nwant: %s", rawBody, want)
	}
	if !strings.Contains(string(rawBody), `"port":443`) {
		t.Fatalf("tcp dispatch is missing the port: %s", rawBody)
	}

	// GET job echoes protocol/port.
	resp, body = h.get("/api/v1/jobs/" + created.ID)
	got := decodeJSONResponse[model.JobResponse](t, resp, body).Job
	if got.Protocol != model.ProtocolTCP || got.Port == nil || *got.Port != 443 {
		t.Fatalf("fetched protocol/port = %s/%v", got.Protocol, got.Port)
	}

	// History includes protocol/port.
	resp, body = h.get("/api/v1/jobs")
	list := decodeJSONResponse[model.JobList](t, resp, body)
	if len(list.Jobs) != 1 || list.Jobs[0].Protocol != model.ProtocolTCP || list.Jobs[0].Port == nil || *list.Jobs[0].Port != 443 {
		t.Fatalf("history item = %+v", list.Jobs)
	}

	// Export includes protocol/port on the job.
	resp, body = h.get("/api/v1/jobs/" + created.ID + "/export")
	export := decodeJSONResponse[model.JobExport](t, resp, body)
	if export.Job.Protocol != model.ProtocolTCP || export.Job.Port == nil || *export.Job.Port != 443 {
		t.Fatalf("export protocol/port = %s/%v", export.Job.Protocol, export.Job.Port)
	}
}

func TestJobUDPExactDispatch(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1))
	port := model.DefaultUDPPort
	resp, body := h.createJob(protocolJobRequest(model.ProtocolUDP, &port))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create udp job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Status != model.JobCompleted || final.Protocol != model.ProtocolUDP || final.Port == nil || *final.Port != port {
		t.Fatalf("udp job = %+v", final)
	}
	dispatched, rawBody := a1.lastTraceRequest()
	if dispatched.Protocol != model.ProtocolUDP || dispatched.Port == nil || *dispatched.Port != port {
		t.Fatalf("dispatched udp request = %s/%v", dispatched.Protocol, dispatched.Port)
	}
	want, err := json.Marshal(expectedAgentRequest(id, model.ProtocolUDP, &port))
	if err != nil {
		t.Fatal(err)
	}
	if string(rawBody) != string(want) {
		t.Fatalf("dispatched body mismatch:\n got: %s\nwant: %s", rawBody, want)
	}
}

func TestJobICMPDispatchOmitsPort(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1))
	resp, body := h.createJob(protocolJobRequest(model.ProtocolICMP, nil))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create icmp job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Status != model.JobCompleted || final.Protocol != model.ProtocolICMP || final.Port != nil {
		t.Fatalf("icmp job = %+v", final)
	}
	dispatched, rawBody := a1.lastTraceRequest()
	if dispatched.Protocol != model.ProtocolICMP || dispatched.Port != nil {
		t.Fatalf("dispatched icmp request = %s/%v", dispatched.Protocol, dispatched.Port)
	}
	want, err := json.Marshal(expectedAgentRequest(id, model.ProtocolICMP, nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(rawBody) != string(want) {
		t.Fatalf("dispatched body mismatch:\n got: %s\nwant: %s", rawBody, want)
	}
	if strings.Contains(string(rawBody), `"port"`) {
		t.Fatalf("icmp dispatch must omit the port field entirely: %s", rawBody)
	}
}

func TestJobProtocolPortValidation(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1))
	port := func(v int) *int { return &v }
	cases := []struct {
		name     string
		protocol model.Protocol
		port     *int
	}{
		{"tcp missing port", model.ProtocolTCP, nil},
		{"udp missing port", model.ProtocolUDP, nil},
		{"tcp zero port", model.ProtocolTCP, port(0)},
		{"tcp port above max", model.ProtocolTCP, port(model.MaxPort + 1)},
		{"udp negative port", model.ProtocolUDP, port(-1)},
		{"icmp with port", model.ProtocolICMP, port(443)},
		{"invalid protocol", model.Protocol("gre"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := h.createJob(protocolJobRequest(tc.protocol, tc.port))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", resp.StatusCode, body)
			}
			envelope := decodeJSONResponse[model.ErrorResponse](t, resp, body)
			if envelope.Error == nil || envelope.Error.Code != model.ErrInvalidRequest {
				t.Fatalf("unexpected error: %+v", envelope.Error)
			}
		})
	}
	if a1.traceCount() != 0 {
		t.Fatalf("rejected jobs must never reach the Agent")
	}

	// Bounds accepted.
	for _, value := range []int{model.MinPort, model.MaxPort} {
		boundary := value
		resp, body := h.createJob(protocolJobRequest(model.ProtocolTCP, &boundary))
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("tcp port %d status = %d body=%s", value, resp.StatusCode, body)
		}
		waitForTerminalJob(t, h.manager, decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID)
	}

	// Port must be a JSON integer, never a string or fraction.
	for _, badPort := range []any{"443", 443.5} {
		req := map[string]any{
			"target_ip": "8.8.8.8", "original_target": "dns.example",
			"node_ids": []string{"node-one"}, "protocol": "tcp", "port": badPort,
			"max_hops": 30, "queries": 3, "timeout_ms": 60000,
		}
		resp, body := h.post("/api/v1/jobs", req)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad port %v status = %d body=%s", badPort, resp.StatusCode, body)
		}
	}
}

func TestJobProtocolAllowlist(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(a1), withDocMutation(func(doc map[string]any) {
		doc["limits"] = map[string]any{"allowed_protocols": []any{"tcp"}}
	}))

	resp, body := h.get("/api/v1/session")
	session := decodeJSONResponse[model.Session](t, resp, body)
	if strings.Join(session.Limits.Protocols, ",") != "tcp" {
		t.Fatalf("session protocols = %v", session.Limits.Protocols)
	}

	// ICMP is disabled for this Controller instance.
	resp, body = h.createJob(protocolJobRequest(model.ProtocolICMP, nil))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("disabled protocol status = %d body=%s", resp.StatusCode, body)
	}
	port := 443
	resp, body = h.createJob(protocolJobRequest(model.ProtocolTCP, &port))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("allowed protocol status = %d body=%s", resp.StatusCode, body)
	}
	waitForTerminalJob(t, h.manager, decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID)
}

func TestSessionLimitsProtocolsDefault(t *testing.T) {
	h := newHarness(t, withAgents(newFakeAgent(t, "node-one")))
	resp, body := h.get("/api/v1/session")
	session := decodeJSONResponse[model.Session](t, resp, body)
	if strings.Join(session.Limits.Protocols, ",") != "icmp,tcp,udp" {
		t.Fatalf("default session protocols = %v", session.Limits.Protocols)
	}
}

func TestAgentResponseProtocolPortMismatch(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(resp *model.AgentTraceResponse)
	}{
		{"protocol mismatch", func(resp *model.AgentTraceResponse) { resp.Protocol = model.ProtocolUDP }},
		{"port mismatch", func(resp *model.AgentTraceResponse) { resp.Port = intPtr(8443) }},
		{"missing port", func(resp *model.AgentTraceResponse) { resp.Port = nil }},
		{"icmp port echoed", func(resp *model.AgentTraceResponse) { resp.Port = intPtr(443) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a1 := newFakeAgent(t, "node-one")
			a1.setTraceHandler(func(w http.ResponseWriter, _ *http.Request, req model.AgentTraceRequest) {
				resp := completedTraceResponse(req)
				tc.mutate(&resp)
				writeTestJSON(t, w, resp)
			})
			h := newHarness(t, withAgents(a1))
			var port *int
			protocol := model.ProtocolTCP
			if tc.name == "icmp port echoed" {
				protocol = model.ProtocolICMP
			} else {
				value := 443
				port = &value
			}
			resp, body := h.createJob(protocolJobRequest(protocol, port))
			if resp.StatusCode != http.StatusAccepted {
				t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
			}
			id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
			final := waitForTerminalJob(t, h.manager, id)
			if final.Nodes[0].Status != model.NodeFailed {
				t.Fatalf("node status = %q, want failed", final.Nodes[0].Status)
			}
			if final.Nodes[0].Error == nil || final.Nodes[0].Error.Code != model.ErrParseError {
				t.Fatalf("unexpected node error: %+v", final.Nodes[0].Error)
			}
		})
	}
}
