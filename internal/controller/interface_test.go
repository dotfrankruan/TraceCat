package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func expectedAgentRequestWithInterface(jobID string, protocol model.Protocol, port *int, iface string) model.AgentTraceRequest {
	req := expectedAgentRequest(jobID, protocol, port)
	req.Interface = iface
	return req
}

func nodeInterfacesByName(nodes []model.NodeResult) map[string]string {
	out := make(map[string]string, len(nodes))
	for _, node := range nodes {
		out[node.NodeID] = node.Interface
	}
	return out
}

func TestRegistryCachesAndFiltersAgentInterfaces(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setInterfaces([]string{"eth0", "eth0", "eth1", "bad name", "", "lo", "waytoolonginterfacename"})
	h := newHarness(t, withAgents(a1))

	h.registry.CheckAll(context.Background())
	got := h.registry.Interfaces("node-one")
	want := []string{"eth0", "eth1", "lo"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("cached interfaces = %v, want %v", got, want)
	}

	infos := h.registry.NodeInfos()
	if len(infos) != 1 || strings.Join(infos[0].Interfaces, ",") != strings.Join(want, ",") {
		t.Fatalf("node info interfaces = %+v", infos)
	}

	// The interactive endpoint exposes the same advertisement.
	resp, body := h.get("/api/v1/nodes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nodes status = %d body=%s", resp.StatusCode, body)
	}
	list := decodeJSONResponse[model.NodeList](t, resp, body)
	if len(list.Nodes) != 1 || strings.Join(list.Nodes[0].Interfaces, ",") != strings.Join(want, ",") {
		t.Fatalf("GET /nodes interfaces = %+v", list.Nodes)
	}

	// An Agent that advertises nothing keeps the list empty.
	a1.setInterfaces(nil)
	h.registry.CheckAll(context.Background())
	if got := h.registry.Interfaces("node-one"); got != nil {
		t.Fatalf("expected no interfaces, got %v", got)
	}

	// An unreachable Agent keeps its last known advertisement.
	a1.setInterfaces([]string{"eth0"})
	h.registry.CheckAll(context.Background())
	a1.srv.Close()
	h.registry.CheckAll(context.Background())
	if got := h.registry.Health("node-one"); got != HealthUnreachable {
		t.Fatalf("health = %q, want unreachable", got)
	}
	if got := h.registry.Interfaces("node-one"); strings.Join(got, ",") != "eth0" {
		t.Fatalf("last-known interfaces were lost: %v", got)
	}
}

func TestJobInterfaceSelectionDispatchesExactValues(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setInterfaces([]string{"eth0", "eth1"})
	a2 := newFakeAgent(t, "node-two")
	a2.setInterfaces([]string{"eth2"})
	h := newHarness(t, withAgents(a1, a2))
	h.registry.CheckAll(context.Background())

	req := model.CreateJobRequest{
		TargetIP:       "8.8.8.8",
		OriginalTarget: "dns.example",
		NodeIDs:        []string{"node-one", "node-two"},
		Protocol:       model.ProtocolICMP,
		NodeInterfaces: map[string]string{
			"node-one": "eth0",
			"node-two": "",
		},
		MaxHops:   30,
		Queries:   3,
		TimeoutMS: 60000,
	}
	resp, body := h.createJob(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	created := decodeJSONResponse[model.JobResponse](t, resp, body).Job
	createdInterfaces := nodeInterfacesByName(created.Nodes)
	if createdInterfaces["node-one"] != "eth0" || createdInterfaces["node-two"] != "" {
		t.Fatalf("created node interfaces = %v", createdInterfaces)
	}

	final := waitForTerminalJob(t, h.manager, created.ID)
	if final.Status != model.JobCompleted {
		t.Fatalf("job status = %q", final.Status)
	}
	finalInterfaces := nodeInterfacesByName(final.Nodes)
	if finalInterfaces["node-one"] != "eth0" || finalInterfaces["node-two"] != "" {
		t.Fatalf("final node interfaces = %v", finalInterfaces)
	}

	// Exact per-node dispatched request bodies.
	dispatchedOne, rawOne := a1.lastTraceRequest()
	if dispatchedOne.Interface != "eth0" {
		t.Fatalf("node-one dispatched interface = %q", dispatchedOne.Interface)
	}
	wantOne, err := json.Marshal(expectedAgentRequestWithInterface(created.ID, model.ProtocolICMP, nil, "eth0"))
	if err != nil {
		t.Fatal(err)
	}
	if string(rawOne) != string(wantOne) {
		t.Fatalf("node-one body mismatch:\n got: %s\nwant: %s", rawOne, wantOne)
	}

	dispatchedTwo, rawTwo := a2.lastTraceRequest()
	if dispatchedTwo.Interface != "" {
		t.Fatalf("node-two dispatched interface = %q", dispatchedTwo.Interface)
	}
	wantTwoReq := expectedAgentRequest(created.ID, model.ProtocolICMP, nil)
	wantTwoReq.NodeID = "node-two"
	wantTwo, err := json.Marshal(wantTwoReq)
	if err != nil {
		t.Fatal(err)
	}
	if string(rawTwo) != string(wantTwo) {
		t.Fatalf("node-two body mismatch:\n got: %s\nwant: %s", rawTwo, wantTwo)
	}
	if strings.Contains(string(rawTwo), `"interface"`) {
		t.Fatalf("automatic routing must omit the interface field entirely: %s", rawTwo)
	}

	// Persisted job (GET after completion) and export keep the selection.
	resp, body = h.get("/api/v1/jobs/" + created.ID)
	got := decodeJSONResponse[model.JobResponse](t, resp, body).Job
	if ifaces := nodeInterfacesByName(got.Nodes); ifaces["node-one"] != "eth0" || ifaces["node-two"] != "" {
		t.Fatalf("stored node interfaces = %v", ifaces)
	}
	resp, body = h.get("/api/v1/jobs/" + created.ID + "/export")
	export := decodeJSONResponse[model.JobExport](t, resp, body)
	if ifaces := nodeInterfacesByName(export.Job.Nodes); ifaces["node-one"] != "eth0" || ifaces["node-two"] != "" {
		t.Fatalf("exported node interfaces = %v", ifaces)
	}
}

func TestJobInterfaceAutoOmitsField(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setInterfaces([]string{"eth0"})
	h := newHarness(t, withAgents(a1))
	h.registry.CheckAll(context.Background())

	resp, body := h.createJob(protocolJobRequest(model.ProtocolICMP, nil))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Nodes[0].Interface != "" {
		t.Fatalf("auto node interface = %q, want empty", final.Nodes[0].Interface)
	}
	dispatched, raw := a1.lastTraceRequest()
	if dispatched.Interface != "" {
		t.Fatalf("dispatched interface = %q", dispatched.Interface)
	}
	want, err := json.Marshal(expectedAgentRequest(id, model.ProtocolICMP, nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(want) {
		t.Fatalf("auto body mismatch:\n got: %s\nwant: %s", raw, want)
	}
	if strings.Contains(string(raw), `"interface"`) {
		t.Fatalf("auto dispatch must omit the interface field: %s", raw)
	}
}

func TestJobInterfaceSelectionValidation(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setInterfaces([]string{"eth0", "eth1"})
	h := newHarness(t, withAgents(a1))
	h.registry.CheckAll(context.Background())

	cases := []struct {
		name       string
		interfaces map[string]string
	}{
		{"unknown node key", map[string]string{"ghost-node": "eth0"}},
		{"not advertised", map[string]string{"node-one": "eth9"}},
		{"loopback style not advertised", map[string]string{"node-one": "lo"}},
		{"syntactically invalid", map[string]string{"node-one": "bad name"}},
		{"too long", map[string]string{"node-one": strings.Repeat("x", model.MaxInterfaceNameLen+1)}},
		{"path-like", map[string]string{"node-one": "../../eth0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := protocolJobRequest(model.ProtocolICMP, nil)
			req.NodeInterfaces = tc.interfaces
			resp, body := h.createJob(req)
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
		t.Fatalf("rejected interface selections must never reach the Agent")
	}

	// An explicitly empty value means automatic routing and is accepted.
	req := protocolJobRequest(model.ProtocolICMP, nil)
	req.NodeInterfaces = map[string]string{"node-one": ""}
	resp, body := h.createJob(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("empty selection status = %d body=%s", resp.StatusCode, body)
	}
	waitForTerminalJob(t, h.manager, decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID)
}

func TestJobInterfaceResponseMismatchFailsOnlyThatNode(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setInterfaces([]string{"eth0", "eth1"})
	a1.setTraceHandler(func(w http.ResponseWriter, _ *http.Request, req model.AgentTraceRequest) {
		resp := completedTraceResponse(req)
		if req.Interface != "" {
			resp.Interface = "eth1" // wrong echo
		}
		writeTestJSON(t, w, resp)
	})
	a2 := newFakeAgent(t, "node-two")
	a2.setInterfaces([]string{"eth0"})
	h := newHarness(t, withAgents(a1, a2))
	h.registry.CheckAll(context.Background())

	req := model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs:        []string{"node-one", "node-two"},
		Protocol:       model.ProtocolICMP,
		NodeInterfaces: map[string]string{"node-one": "eth0"},
		MaxHops:        30, Queries: 3, TimeoutMS: 60000,
	}
	resp, body := h.createJob(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Status != model.JobPartial {
		t.Fatalf("job status = %q, want partial", final.Status)
	}
	ifaces := nodeInterfacesByName(final.Nodes)
	if ifaces["node-one"] != "eth0" || ifaces["node-two"] != "" {
		t.Fatalf("node interfaces = %v", ifaces)
	}
	for _, node := range final.Nodes {
		switch node.NodeID {
		case "node-one":
			if node.Status != model.NodeFailed || node.Error == nil || node.Error.Code != model.ErrParseError {
				t.Fatalf("node-one = %+v", node)
			}
		case "node-two":
			if node.Status != model.NodeCompleted {
				t.Fatalf("node-two = %+v", node)
			}
		}
	}
}

func TestJobInterfaceAutoEchoMismatchFailsNode(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setInterfaces([]string{"eth0"})
	a1.setTraceHandler(func(w http.ResponseWriter, _ *http.Request, req model.AgentTraceRequest) {
		resp := completedTraceResponse(req)
		resp.Interface = "eth0" // the Agent must omit it for automatic routing
		writeTestJSON(t, w, resp)
	})
	h := newHarness(t, withAgents(a1))
	h.registry.CheckAll(context.Background())

	resp, body := h.createJob(protocolJobRequest(model.ProtocolICMP, nil))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Nodes[0].Status != model.NodeFailed || final.Nodes[0].Error == nil || final.Nodes[0].Error.Code != model.ErrParseError {
		t.Fatalf("node = %+v", final.Nodes[0])
	}
}

func TestJobInterfaceRequestMapIsCopied(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setInterfaces([]string{"eth0", "eth1"})
	h := newHarness(t, withAgents(a1))
	h.registry.CheckAll(context.Background())

	req := protocolJobRequest(model.ProtocolICMP, nil)
	req.NodeInterfaces = map[string]string{"node-one": "eth0"}
	resp, body := h.createJob(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID

	// Mutating the caller's map must not affect the scheduled job (the manager
	// deep-copies selections into the plan).
	req.NodeInterfaces["node-one"] = "eth1"
	delete(req.NodeInterfaces, "node-one")

	final := waitForTerminalJob(t, h.manager, id)
	if final.Nodes[0].Interface != "eth0" {
		t.Fatalf("job interface changed with the request map: %q", final.Nodes[0].Interface)
	}
	dispatched, _ := a1.lastTraceRequest()
	if dispatched.Interface != "eth0" {
		t.Fatalf("dispatched interface = %q", dispatched.Interface)
	}
}

func TestStoreNodeInterfaceRoundTrip(t *testing.T) {
	store := testStore(t, 10)
	ctx := context.Background()
	job := sampleJob("abababababababababababababababab", testNow(), model.JobCompleted)
	job.Nodes[0].Interface = "eth0"
	if err := store.SaveJob(ctx, job, nil); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}
	got, err := store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.Nodes[0].Interface != "eth0" {
		t.Fatalf("stored interface = %q", got.Nodes[0].Interface)
	}

	// Auto selection persists as empty and omits the JSON field.
	job.Nodes[0].Interface = ""
	if err := store.SaveJob(ctx, job, nil); err != nil {
		t.Fatalf("SaveJob auto: %v", err)
	}
	got, err = store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJob auto: %v", err)
	}
	if got.Nodes[0].Interface != "" {
		t.Fatalf("auto interface = %q, want empty", got.Nodes[0].Interface)
	}
}

func testNow() time.Time { return time.Now().UTC() }

func TestJobInterfaceInvalidEchoFailsNode(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a1.setInterfaces([]string{"eth0"})
	a1.setTraceHandler(func(w http.ResponseWriter, _ *http.Request, req model.AgentTraceRequest) {
		resp := completedTraceResponse(req)
		resp.Interface = "bad name" // syntactically invalid echo
		writeTestJSON(t, w, resp)
	})
	h := newHarness(t, withAgents(a1))
	h.registry.CheckAll(context.Background())

	req := protocolJobRequest(model.ProtocolICMP, nil)
	req.NodeInterfaces = map[string]string{"node-one": "eth0"}
	resp, body := h.createJob(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Nodes[0].Status != model.NodeFailed || final.Nodes[0].Error == nil || final.Nodes[0].Error.Code != model.ErrParseError {
		t.Fatalf("node = %+v", final.Nodes[0])
	}
	// The selected interface is still recorded honestly even though the node
	// failed contract validation.
	if final.Nodes[0].Interface != "eth0" {
		t.Fatalf("stored interface = %q", final.Nodes[0].Interface)
	}
}
