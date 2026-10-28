package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	jobPersistTimeout = 5 * time.Second
	defaultJobMargin  = 10 * time.Second
	maxHopsReported   = 64
	maxProbesPerHop   = 16
	maxMPLSLabels     = 8
	maxNodeDurationMS = int64(24 * 60 * 60 * 1000)
)

// Manager owns the job lifecycle: validation, bounded dispatch to Agents,
// per-node result normalization, aggregation, persistence and SSE publishing.
type Manager struct {
	cfg      *Config
	store    *Store
	registry *Registry
	client   *AgentClient
	hub      *Hub
	logger   *slog.Logger
	now      func() time.Time
	idGen    func() (string, error)
	margin   time.Duration
	policy   ipguard.Policy

	jobSem   chan struct{}
	traceSem chan struct{}
	limiter  *rateLimiter

	baseCtx    context.Context
	baseCancel context.CancelFunc
	wg         sync.WaitGroup

	mu       sync.Mutex
	jobs     map[string]*jobState
	shutdown bool
}

type jobState struct {
	mu        sync.Mutex
	persistMu sync.Mutex
	job       model.Job
	raw       map[string]json.RawMessage
	nodeIdx   map[string]int
	cancel    context.CancelFunc
	cancelled bool
	done      bool
	// releaseOnce guarantees the global job slot is released exactly once.
	// The slot is released as soon as all node workers finish, before the
	// terminal job state becomes visible, so a client that observes a finished
	// job can immediately start another one without a transient 503.
	releaseOnce sync.Once
}

// ManagerOption customizes a Manager (tests inject clocks/id generators and a
// shorter timeout margin).
type ManagerOption func(*Manager)

// WithManagerLogger injects the structured logger.
func WithManagerLogger(logger *slog.Logger) ManagerOption {
	return func(m *Manager) {
		if logger != nil {
			m.logger = logger
		}
	}
}

// WithManagerClock injects a clock.
func WithManagerClock(now func() time.Time) ManagerOption {
	return func(m *Manager) { m.now = now }
}

// WithManagerIDGenerator injects the job id source.
func WithManagerIDGenerator(gen func() (string, error)) ManagerOption {
	return func(m *Manager) { m.idGen = gen }
}

// WithManagerTimeoutMargin overrides the Controller->Agent timeout margin.
func WithManagerTimeoutMargin(margin time.Duration) ManagerOption {
	return func(m *Manager) { m.margin = margin }
}

// NewManager builds the job manager.
func NewManager(cfg *Config, store *Store, registry *Registry, client *AgentClient, hub *Hub, logger *slog.Logger, opts ...ManagerOption) *Manager {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	policy, err := ipguard.NewPolicy(nil)
	if err != nil {
		panic(err)
	}
	baseCtx, baseCancel := context.WithCancel(context.Background())
	m := &Manager{
		cfg:        cfg,
		store:      store,
		registry:   registry,
		client:     client,
		hub:        hub,
		logger:     logger,
		now:        time.Now,
		idGen:      randomJobID,
		margin:     defaultJobMargin,
		policy:     policy,
		jobSem:     make(chan struct{}, cfg.Limits.MaxConcurrentJobs),
		traceSem:   make(chan struct{}, cfg.Limits.MaxConcurrentTraces),
		limiter:    newRateLimiter(float64(cfg.Limits.MaxJobsPerMinute)),
		baseCtx:    baseCtx,
		baseCancel: baseCancel,
		jobs:       make(map[string]*jobState),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func randomJobID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// CreateJob validates and schedules a distributed trace job.
func (m *Manager) CreateJob(ctx context.Context, principal *Principal, clientIP string, req *model.CreateJobRequest) (*model.Job, *model.APIError) {
	plan, apiErr := m.validateCreateJob(req)
	if apiErr != nil {
		return nil, apiErr
	}

	rateKey := clientIP
	if principal != nil {
		if principal.User.Subject != "" {
			rateKey = "user:" + principal.User.Subject
		} else if principal.User.Email != "" {
			rateKey = "email:" + principal.User.Email
		}
	}
	if !m.limiter.Allow(rateKey) {
		return nil, model.NewError(model.ErrRateLimited, "job creation rate limit exceeded")
	}

	select {
	case m.jobSem <- struct{}{}:
	default:
		return nil, model.NewError(model.ErrBusy, "too many concurrent jobs; try again later")
	}

	jobID, err := m.idGen()
	if err != nil || model.ValidateJobID(jobID) != nil {
		m.releaseJobSlot()
		return nil, model.NewError(model.ErrInternal, "internal error")
	}

	now := m.now().UTC()
	job := &model.Job{
		SchemaVersion:  model.ControllerSchemaVersion,
		ID:             jobID,
		Status:         model.JobPending,
		TargetIP:       plan.target.String(),
		OriginalTarget: plan.originalTarget,
		Family:         plan.family,
		Protocol:       plan.protocol,
		Port:           clonePort(plan.port),
		MaxHops:        plan.maxHops,
		Queries:        plan.queries,
		TimeoutMS:      plan.timeoutMS,
		CreatedAt:      now.Format(time.RFC3339Nano),
		CreatedBy:      safeCreatedBy(principal),
		Nodes:          make([]model.NodeResult, 0, len(plan.nodeIDs)),
	}
	for _, nodeID := range plan.nodeIDs {
		agent, _ := m.registry.Get(nodeID)
		job.Nodes = append(job.Nodes, model.NodeResult{
			NodeID:   agent.ID,
			NodeName: agent.Name,
			Location: agent.Location,
			Provider: agent.Provider,
			Status:   model.NodePending,
		})
	}
	job.Summary = model.SummarizeJob(job.Nodes)

	jobCtx, cancel := context.WithCancel(m.baseCtx)
	st := &jobState{
		job:     *job,
		raw:     make(map[string]json.RawMessage),
		nodeIdx: make(map[string]int, len(job.Nodes)),
		cancel:  cancel,
	}
	for i := range job.Nodes {
		st.nodeIdx[job.Nodes[i].NodeID] = i
	}

	m.mu.Lock()
	if m.shutdown {
		m.mu.Unlock()
		cancel()
		m.releaseJobSlot()
		return nil, model.NewError(model.ErrBusy, "server is shutting down")
	}
	m.jobs[jobID] = st
	m.mu.Unlock()

	if err := m.persistNow(st); err != nil {
		m.mu.Lock()
		delete(m.jobs, jobID)
		m.mu.Unlock()
		cancel()
		m.releaseJobSlot()
		m.logger.Error("could not persist new job", "job_id", jobID)
		return nil, model.NewError(model.ErrInternal, "internal error")
	}

	snapshot := m.snapshot(st)
	m.hub.Publish(jobID, snapshot)

	m.wg.Add(1)
	go m.runJob(jobCtx, st)

	return &snapshot, nil
}

type createPlan struct {
	target         netip.Addr
	family         model.IPFamily
	protocol       model.Protocol
	port           *int
	nodeIDs        []string
	originalTarget string
	maxHops        int
	queries        int
	timeoutMS      int
}

func (m *Manager) validateCreateJob(req *model.CreateJobRequest) (*createPlan, *model.APIError) {
	if req == nil {
		return nil, model.NewError(model.ErrInvalidRequest, "request body is required")
	}
	limits := m.cfg.Limits
	protocol := req.Protocol
	if !protocol.Valid() {
		return nil, model.NewError(model.ErrInvalidRequest, "invalid protocol")
	}
	if !m.cfg.IsProtocolAllowed(protocol) {
		return nil, model.NewError(model.ErrInvalidRequest, fmt.Sprintf("protocol %q is not enabled", protocol))
	}
	if err := model.ValidatePortForProtocol(protocol, req.Port); err != nil {
		var apiErr *model.APIError
		if errors.As(err, &apiErr) {
			return nil, apiErr
		}
		return nil, model.NewError(model.ErrInvalidRequest, "invalid port")
	}
	if req.MaxHops < model.MinMaxHops || req.MaxHops > limits.MaxHops {
		return nil, model.NewError(model.ErrInvalidRequest, fmt.Sprintf("max_hops must be between %d and %d", model.MinMaxHops, limits.MaxHops))
	}
	if req.Queries < model.MinQueries || req.Queries > limits.MaxQueries {
		return nil, model.NewError(model.ErrInvalidRequest, fmt.Sprintf("queries must be between %d and %d", model.MinQueries, limits.MaxQueries))
	}
	if req.TimeoutMS < limits.MinExecutionMS || req.TimeoutMS > limits.MaxExecutionMS {
		return nil, model.NewError(model.ErrInvalidRequest,
			fmt.Sprintf("timeout_ms must be between %d and %d", limits.MinExecutionMS, limits.MaxExecutionMS))
	}

	target, apiErr := ParseTargetIP(m.policy, req.TargetIP)
	if apiErr != nil {
		return nil, apiErr
	}
	original := req.OriginalTarget
	if original == "" {
		original = target.String()
	}
	validated, err := model.ValidateOriginalTarget(original)
	if err != nil {
		return nil, model.NewError(model.ErrInvalidRequest, "original_target is invalid")
	}

	if len(req.NodeIDs) == 0 {
		return nil, model.NewError(model.ErrInvalidRequest, "node_ids must not be empty")
	}
	if len(req.NodeIDs) > limits.MaxNodesPerJob {
		return nil, model.NewError(model.ErrInvalidRequest, fmt.Sprintf("at most %d nodes may be targeted", limits.MaxNodesPerJob))
	}
	seen := make(map[string]struct{}, len(req.NodeIDs))
	nodeIDs := make([]string, 0, len(req.NodeIDs))
	for _, nodeID := range req.NodeIDs {
		if _, dup := seen[nodeID]; dup {
			return nil, model.NewError(model.ErrInvalidRequest, "node_ids contains duplicates")
		}
		seen[nodeID] = struct{}{}
		if model.ValidateNodeID(nodeID) != nil {
			return nil, model.NewError(model.ErrForbidden, "unknown node")
		}
		agent, ok := m.registry.Get(nodeID)
		if !ok || !agent.IsEnabled() {
			return nil, model.NewError(model.ErrForbidden, "unknown or disabled node")
		}
		nodeIDs = append(nodeIDs, nodeID)
	}

	return &createPlan{
		target:         target,
		family:         model.FamilyOf(target),
		protocol:       protocol,
		port:           clonePort(req.Port),
		nodeIDs:        nodeIDs,
		originalTarget: validated,
		maxHops:        req.MaxHops,
		queries:        req.Queries,
		timeoutMS:      req.TimeoutMS,
	}, nil
}

// clonePort copies an optional destination port so job snapshots never alias a
// caller-owned pointer.
func clonePort(port *int) *int {
	if port == nil {
		return nil
	}
	value := *port
	return &value
}

func safeCreatedBy(principal *Principal) string {
	if principal == nil {
		return ""
	}
	if principal.User.Email != "" {
		return model.SanitizeText(principal.User.Email, 254)
	}
	return model.SanitizeText(principal.User.Subject, 128)
}

func (m *Manager) releaseJobSlot() {
	select {
	case <-m.jobSem:
	default:
	}
}

func (m *Manager) snapshot(st *jobState) model.Job {
	st.mu.Lock()
	defer st.mu.Unlock()
	return cloneJob(st.job)
}

func cloneJob(job model.Job) model.Job {
	clone := job
	clone.Nodes = make([]model.NodeResult, len(job.Nodes))
	copy(clone.Nodes, job.Nodes)
	return clone
}

func (m *Manager) rawSnapshot(st *jobState) map[string]json.RawMessage {
	st.mu.Lock()
	defer st.mu.Unlock()
	return copyRawResults(st.raw)
}

func copyRawResults(in map[string]json.RawMessage) map[string]json.RawMessage {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func jobNodeIDs(job *model.Job) []string {
	ids := make([]string, 0, len(job.Nodes))
	for i := range job.Nodes {
		ids = append(ids, job.Nodes[i].NodeID)
	}
	return ids
}

func (m *Manager) runJob(ctx context.Context, st *jobState) {
	defer m.wg.Done()
	defer st.releaseOnce.Do(m.releaseJobSlot)
	defer st.cancel()

	st.mu.Lock()
	jobID := st.job.ID
	now := m.now().UTC().Format(time.RFC3339Nano)
	st.job.Status = model.JobRunning
	st.job.StartedAt = now
	for i := range st.job.Nodes {
		if st.job.Nodes[i].Status == model.NodePending {
			st.job.Nodes[i].Status = model.NodeRunning
			st.job.Nodes[i].StartedAt = now
		}
	}
	st.job.Summary = model.SummarizeJob(st.job.Nodes)
	nodeIDs := jobNodeIDs(&st.job)
	st.mu.Unlock()
	m.broadcastAndPersist(st)

	var nodeWG sync.WaitGroup
	for _, nodeID := range nodeIDs {
		nodeWG.Add(1)
		go func(nodeID string) {
			defer nodeWG.Done()
			m.runNode(ctx, st, nodeID)
		}(nodeID)
	}
	nodeWG.Wait()
	// Free the concurrency slot before publishing the terminal state so a client
	// that just observed completion can immediately submit the next job.
	st.releaseOnce.Do(m.releaseJobSlot)

	st.mu.Lock()
	if ctx.Err() != nil {
		st.cancelled = true
	}
	for i := range st.job.Nodes {
		// Defensive: no node may remain pending/running after all workers
		// returned.
		if !st.job.Nodes[i].Status.Terminal() {
			st.job.Nodes[i].Status = model.NodeCancelled
			st.job.Nodes[i].Error = model.NewError(model.ErrCancelled, "cancelled")
		}
	}
	summary := model.SummarizeJob(st.job.Nodes)
	st.job.Summary = summary
	switch {
	case st.cancelled:
		st.job.Status = model.JobCancelled
	case summary.Total > 0 && summary.Completed == summary.Total:
		st.job.Status = model.JobCompleted
	case summary.Completed > 0:
		st.job.Status = model.JobPartial
	default:
		st.job.Status = model.JobFailed
	}
	st.job.EndedAt = m.now().UTC().Format(time.RFC3339Nano)
	st.done = true
	final := cloneJob(st.job)
	raw := copyRawResults(st.raw)
	st.mu.Unlock()

	m.hub.Publish(jobID, final)
	if err := m.store.SaveJob(context.Background(), &final, raw); err != nil {
		m.logger.Error("could not persist finished job", "job_id", jobID)
	}
	m.hub.Close(jobID)
	m.mu.Lock()
	delete(m.jobs, jobID)
	m.mu.Unlock()
	m.logger.Info("job finished", "job_id", jobID, "status", string(final.Status))
}

func (m *Manager) runNode(ctx context.Context, st *jobState, nodeID string) {
	agent, ok := m.registry.Get(nodeID)
	if !ok {
		now := m.now().UTC()
		m.finishNode(st, nodeID, model.NodeFailed, nil, model.NewError(ErrAgentError, "unknown node"), &now, &now)
		return
	}

	select {
	case m.traceSem <- struct{}{}:
		defer func() { <-m.traceSem }()
	case <-ctx.Done():
		now := m.now().UTC()
		m.finishNode(st, nodeID, model.NodeCancelled, nil, model.NewError(model.ErrCancelled, "cancelled"), &now, &now)
		return
	}

	st.mu.Lock()
	job := st.job
	st.mu.Unlock()

	req := &model.AgentTraceRequest{
		SchemaVersion: model.AgentSchemaVersion,
		JobID:         job.ID,
		NodeID:        agent.ID,
		TargetIP:      job.TargetIP,
		Family:        job.Family,
		Protocol:      job.Protocol,
		Port:          clonePort(job.Port),
		MaxHops:       job.MaxHops,
		Queries:       job.Queries,
		TimeoutMS:     job.TimeoutMS,
	}
	timeout := time.Duration(job.TimeoutMS)*time.Millisecond + m.margin
	if maxTimeout := time.Duration(agent.RequestTimeoutMS) * time.Millisecond; maxTimeout > 0 && timeout > maxTimeout {
		timeout = maxTimeout
	}
	started := m.now().UTC()
	resp, err := m.client.Trace(ctx, agent, req, timeout)
	ended := m.now().UTC()
	if err != nil {
		status, apiErr := classifyAgentFailure(err, ctx)
		m.finishNode(st, nodeID, status, nil, apiErr, &started, &ended)
		return
	}
	result, raw := m.buildNodeResult(agent, resp, job.TargetIP, started, ended)
	if len(raw) > 0 {
		st.mu.Lock()
		if _, exists := st.raw[nodeID]; !exists {
			st.raw[nodeID] = raw
		}
		st.mu.Unlock()
	}
	m.finishNode(st, nodeID, result.Status, &result, nil, &started, &ended)
}

func (m *Manager) finishNode(st *jobState, nodeID string, status model.NodeStatus, result *model.NodeResult, apiErr *model.APIError, started, ended *time.Time) {
	st.mu.Lock()
	idx, ok := st.nodeIdx[nodeID]
	if !ok || st.done {
		st.mu.Unlock()
		return
	}
	node := &st.job.Nodes[idx]
	if node.Status.Terminal() {
		st.mu.Unlock()
		return
	}
	if result != nil {
		node.Hops = result.Hops
		node.Summary = result.Summary
		node.DurationMS = result.DurationMS
		node.NextTraceVersion = result.NextTraceVersion
		node.ParserSchema = result.ParserSchema
	}
	node.Status = status
	if started != nil {
		node.StartedAt = started.UTC().Format(time.RFC3339Nano)
	}
	if ended != nil {
		node.EndedAt = ended.UTC().Format(time.RFC3339Nano)
		if started != nil && node.DurationMS == nil {
			duration := ended.Sub(*started).Milliseconds()
			if duration < 0 {
				duration = 0
			}
			node.DurationMS = &duration
		}
	}
	if apiErr != nil {
		node.Error = model.NewError(apiErr.Code, apiErr.Message)
	}
	st.job.Summary = model.SummarizeJob(st.job.Nodes)
	st.mu.Unlock()
	m.broadcastAndPersist(st)
}

func classifyAgentFailure(err error, ctx context.Context) (model.NodeStatus, *model.APIError) {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return model.NodeCancelled, model.NewError(model.ErrCancelled, "cancelled")
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return model.NodeTimedOut, model.NewError(model.ErrTimeout, "agent request timed out")
	}
	var callErr *agentCallError
	if errors.As(err, &callErr) {
		switch callErr.kind {
		case agentErrTimeout:
			return model.NodeTimedOut, model.NewError(model.ErrTimeout, callErr.message)
		case agentErrCancelled:
			return model.NodeCancelled, model.NewError(model.ErrCancelled, callErr.message)
		case agentErrUnreachable:
			return model.NodeFailed, model.NewError(model.ErrAgentUnreachable, callErr.message)
		case agentErrTooLarge:
			return model.NodeFailed, model.NewError(ErrAgentError, callErr.message)
		default:
			code := callErr.code
			if code == "" {
				code = ErrAgentError
			}
			return model.NodeFailed, model.NewError(code, callErr.message)
		}
	}
	return model.NodeFailed, model.NewError(model.ErrAgentUnreachable, "agent unreachable")
}

func (m *Manager) buildNodeResult(agent *AgentConfig, resp *model.AgentTraceResponse, targetIP string, started, ended time.Time) (model.NodeResult, json.RawMessage) {
	result := model.NodeResult{
		NodeID:   agent.ID,
		NodeName: agent.Name,
		Location: agent.Location,
		Provider: agent.Provider,
		Status:   resp.Status,
	}
	result.StartedAt = normalizeTimestamp(resp.StartedAt)
	result.EndedAt = normalizeTimestamp(resp.EndedAt)
	if resp.DurationMS > 0 {
		duration := resp.DurationMS
		if duration > maxNodeDurationMS {
			duration = maxNodeDurationMS
		}
		result.DurationMS = &duration
	}
	result.NextTraceVersion = model.SanitizeText(resp.NextTraceVersion, 64)
	result.ParserSchema = model.SanitizeText(resp.ParserSchema, 64)
	result.Hops = sanitizeHops(resp.Hops, targetIP)
	summary := model.Summarize(result.Hops, targetIP)
	result.Summary = &summary
	if resp.Status != model.NodeCompleted {
		result.Error = sanitizeAgentError(resp.Error, resp.Status)
	}
	if result.StartedAt == "" {
		result.StartedAt = started.UTC().Format(time.RFC3339Nano)
	}
	if result.EndedAt == "" {
		result.EndedAt = ended.UTC().Format(time.RFC3339Nano)
	}
	if result.DurationMS == nil {
		duration := ended.Sub(started).Milliseconds()
		if duration < 0 {
			duration = 0
		}
		result.DurationMS = &duration
	}

	var raw json.RawMessage
	if len(resp.RawResult) > 0 && string(resp.RawResult) != "null" && json.Valid(resp.RawResult) {
		if int64(len(resp.RawResult)) <= int64(m.cfg.Limits.MaxRawResultBytes) {
			raw = resp.RawResult
		}
	}
	return result, raw
}

func sanitizeAgentError(apiErr *model.APIError, status model.NodeStatus) *model.APIError {
	allowed := map[model.ErrorCode]struct{}{
		model.ErrNextTraceMissing: {},
		model.ErrNextTraceFailed:  {},
		model.ErrParseError:       {},
		model.ErrTimeout:          {},
		model.ErrCancelled:        {},
		model.ErrOutputTooLarge:   {},
		model.ErrInternal:         {},
	}
	if apiErr != nil {
		if _, ok := allowed[apiErr.Code]; ok {
			return model.NewError(apiErr.Code, apiErr.Message)
		}
	}
	switch status {
	case model.NodeTimedOut:
		return model.NewError(model.ErrTimeout, "trace timed out")
	case model.NodeCancelled:
		return model.NewError(model.ErrCancelled, "trace cancelled")
	case model.NodeFailed:
		return model.NewError(model.ErrNextTraceFailed, "trace failed")
	default:
		return nil
	}
}

func normalizeTimestamp(value string) string {
	value = model.SanitizeText(value, 40)
	if value == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func sanitizeHops(hops []model.Hop, _ string) []model.Hop {
	if len(hops) == 0 {
		return nil
	}
	if len(hops) > maxHopsReported {
		hops = hops[:maxHopsReported]
	}
	out := make([]model.Hop, 0, len(hops))
	for _, hop := range hops {
		if hop.TTL < 1 || hop.TTL > 255 {
			continue
		}
		probes := hop.Probes
		if len(probes) > maxProbesPerHop {
			probes = probes[:maxProbesPerHop]
		}
		cleanProbes := make([]model.Probe, 0, len(probes))
		for i := range probes {
			cleanProbes = append(cleanProbes, sanitizeProbe(probes[i]))
		}
		out = append(out, model.Hop{TTL: hop.TTL, Probes: cleanProbes})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TTL < out[j].TTL })
	return out
}

func sanitizeProbe(probe model.Probe) model.Probe {
	clean := model.Probe{
		Success: probe.Success,
		PTR:     model.SanitizeText(probe.PTR, 253),
		ASName:  model.SanitizeText(probe.ASName, 128),
		Country: model.SanitizeText(probe.Country, 64),
		Region:  model.SanitizeText(probe.Region, 64),
		City:    model.SanitizeText(probe.City, 64),
		Owner:   model.SanitizeText(probe.Owner, 128),
		ISP:     model.SanitizeText(probe.ISP, 128),
		Prefix:  model.SanitizeText(probe.Prefix, 64),
	}
	if probe.RTTMS != nil && validFloat(*probe.RTTMS, 0, 3_600_000) {
		value := *probe.RTTMS
		clean.RTTMS = &value
	}
	if probe.ASN != nil && *probe.ASN > 0 {
		value := *probe.ASN
		clean.ASN = &value
	}
	if probe.Lat != nil && validFloat(*probe.Lat, -90, 90) {
		value := *probe.Lat
		clean.Lat = &value
	}
	if probe.Lng != nil && validFloat(*probe.Lng, -180, 180) {
		value := *probe.Lng
		clean.Lng = &value
	}
	if len(probe.MPLS) > 0 {
		count := len(probe.MPLS)
		if count > maxMPLSLabels {
			count = maxMPLSLabels
		}
		labels := make([]string, 0, count)
		for _, label := range probe.MPLS[:count] {
			if sanitized := model.SanitizeText(label, 64); sanitized != "" {
				labels = append(labels, sanitized)
			}
		}
		if len(labels) > 0 {
			clean.MPLS = labels
		}
	}

	if !probe.Success {
		clean.Address = ""
		clean.RTTMS = nil
		switch probe.ErrorCode {
		case "no_reply", "unreachable", "unknown":
			clean.ErrorCode = probe.ErrorCode
		default:
			clean.ErrorCode = "unknown"
		}
		return clean
	}

	addr, err := ipguard.NormalizeIP(probe.Address)
	if err != nil {
		clean.Success = false
		clean.ErrorCode = "unknown"
		return clean
	}
	clean.Address = addr.String()
	return clean
}

func validFloat(value, min, max float64) bool {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return false
	}
	return value >= min && value <= max
}

func (m *Manager) broadcastAndPersist(st *jobState) {
	snapshot := m.snapshot(st)
	m.hub.Publish(snapshot.ID, snapshot)
	if err := m.persistNow(st); err != nil {
		m.logger.Error("could not persist job update", "job_id", snapshot.ID)
	}
}

func (m *Manager) persistNow(st *jobState) error {
	st.persistMu.Lock()
	defer st.persistMu.Unlock()
	snapshot := m.snapshot(st)
	raw := m.rawSnapshot(st)
	ctx, cancel := context.WithTimeout(context.Background(), jobPersistTimeout)
	defer cancel()
	return m.store.SaveJob(ctx, &snapshot, raw)
}

// GetJob returns the current snapshot (from memory while running, otherwise
// from SQLite).
func (m *Manager) GetJob(ctx context.Context, id string) (*model.Job, *model.APIError) {
	if model.ValidateJobID(id) != nil {
		return nil, model.NewError(model.ErrNotFound, "job not found")
	}
	m.mu.Lock()
	st := m.jobs[id]
	m.mu.Unlock()
	if st != nil {
		snapshot := m.snapshot(st)
		return &snapshot, nil
	}
	job, err := m.store.GetJob(ctx, id)
	if err != nil {
		if errors.Is(err, ErrStoreNotFound) {
			return nil, model.NewError(model.ErrNotFound, "job not found")
		}
		return nil, model.NewError(model.ErrInternal, "internal error")
	}
	return job, nil
}

// ListJobs returns recent job history (no hops).
func (m *Manager) ListJobs(ctx context.Context, limit int) ([]model.JobListItem, *model.APIError) {
	items, err := m.store.ListJobs(ctx, limit)
	if err != nil {
		m.logger.Error("could not list jobs")
		return nil, model.NewError(model.ErrInternal, "internal error")
	}
	return items, nil
}

// Export returns the full job plus bounded raw NextTrace results.
func (m *Manager) Export(ctx context.Context, id string) (*model.JobExport, *model.APIError) {
	if model.ValidateJobID(id) != nil {
		return nil, model.NewError(model.ErrNotFound, "job not found")
	}
	m.mu.Lock()
	st := m.jobs[id]
	m.mu.Unlock()

	var (
		job model.Job
		raw map[string]json.RawMessage
	)
	if st != nil {
		job = m.snapshot(st)
		raw = m.rawSnapshot(st)
	} else {
		stored, err := m.store.GetJob(ctx, id)
		if err != nil {
			if errors.Is(err, ErrStoreNotFound) {
				return nil, model.NewError(model.ErrNotFound, "job not found")
			}
			return nil, model.NewError(model.ErrInternal, "internal error")
		}
		job = *stored
		storedRaw, err := m.store.GetRawResults(ctx, id)
		if err != nil {
			return nil, model.NewError(model.ErrInternal, "internal error")
		}
		raw = storedRaw
	}
	return &model.JobExport{
		SchemaVersion: model.ControllerSchemaVersion,
		ExportedAt:    m.now().UTC().Format(time.RFC3339Nano),
		Job:           job,
		RawResults:    raw,
	}, nil
}

// CancelJob requests cancellation of a pending/running job. It is idempotent
// while the job is still live; terminal jobs yield 409.
func (m *Manager) CancelJob(ctx context.Context, id string) (*model.Job, *model.APIError) {
	if model.ValidateJobID(id) != nil {
		return nil, model.NewError(model.ErrNotFound, "job not found")
	}
	m.mu.Lock()
	st := m.jobs[id]
	m.mu.Unlock()
	if st == nil {
		job, err := m.store.GetJob(ctx, id)
		if err != nil {
			if errors.Is(err, ErrStoreNotFound) {
				return nil, model.NewError(model.ErrNotFound, "job not found")
			}
			return nil, model.NewError(model.ErrInternal, "internal error")
		}
		if jobIsTerminal(job.Status) {
			return nil, model.NewError(model.ErrConflict, "job is already finished")
		}
		return nil, model.NewError(model.ErrConflict, "job is not cancellable")
	}

	st.mu.Lock()
	if st.done || jobIsTerminal(st.job.Status) {
		st.mu.Unlock()
		return nil, model.NewError(model.ErrConflict, "job is already finished")
	}
	if st.cancelled {
		snapshot := cloneJob(st.job)
		st.mu.Unlock()
		return &snapshot, nil
	}
	st.cancelled = true
	cancel := st.cancel
	snapshot := cloneJob(st.job)
	st.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return &snapshot, nil
}

func jobIsTerminal(status model.JobStatus) bool {
	switch status {
	case model.JobCompleted, model.JobPartial, model.JobFailed, model.JobCancelled:
		return true
	default:
		return false
	}
}

// Subscribe returns a snapshot stream for a job's SSE endpoint.
func (m *Manager) Subscribe(id string) (<-chan model.Job, func()) {
	return m.hub.Subscribe(id)
}

// Shutdown cancels all in-flight jobs and waits (bounded by ctx) for them to
// finish. It also closes all SSE subscriptions.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	m.shutdown = true
	m.mu.Unlock()
	m.baseCancel()
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	m.hub.CloseAll()
}
