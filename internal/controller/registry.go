package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

// Health states exposed by GET /api/v1/nodes.
const (
	HealthOK          = "ok"
	HealthDegraded    = "degraded"
	HealthUnreachable = "unreachable"
	HealthUnknown     = "unknown"
	HealthDisabled    = "disabled"
)

// Registry errors surfaced by secure auto-enrollment.
var (
	// ErrStaticNodeCollision is returned when an enrollment request uses the
	// node id of an administratively configured Agent (static config wins).
	ErrStaticNodeCollision = errors.New("controller: node id is statically configured")
	// ErrRegistryHasNoStore is returned when auto-enrollment is attempted before
	// the registry has been connected to the persistent store.
	ErrRegistryHasNoStore = errors.New("controller: registry has no store attached")
)

type nodeHealth struct {
	status           string
	lastSeen         time.Time
	nextTraceVersion string
	// interfaces is the Agent-advertised, allowlisted interface list from the
	// last successful health check. It is used to validate per-node interface
	// selection and is exposed by GET /api/v1/nodes.
	interfaces []string
}

// maxAdvertisedInterfaces bounds how many interfaces are cached/exposed per
// Agent.
const maxAdvertisedInterfaces = 64

// Registry is the Controller node table. Nodes come from two sources:
// administratively validated configuration (static, which always wins on id
// collision) and secure self-enrollment through the enrollment endpoint (auto).
// There is no user-facing registration API.
type Registry struct {
	cfg    *Config
	store  *Store
	client *AgentClient
	logger *slog.Logger
	now    func() time.Time

	mu        sync.RWMutex
	nodes     map[string]*AgentConfig
	order     []string
	health    map[string]nodeHealth
	sources   map[string]model.NodeSource
	staticIDs map[string]struct{}

	wg sync.WaitGroup
}

// NewRegistry builds the node registry from the static configuration. Call
// LoadRegisteredAgents to restore auto-enrolled Agents from SQLite.
func NewRegistry(cfg *Config, client *AgentClient, logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	r := &Registry{
		cfg:       cfg,
		client:    client,
		logger:    logger,
		now:       time.Now,
		nodes:     make(map[string]*AgentConfig, len(cfg.Agents)),
		order:     make([]string, 0, len(cfg.Agents)),
		health:    make(map[string]nodeHealth, len(cfg.Agents)),
		sources:   make(map[string]model.NodeSource, len(cfg.Agents)),
		staticIDs: make(map[string]struct{}, len(cfg.Agents)),
	}
	for i := range cfg.Agents {
		agent := &cfg.Agents[i]
		r.nodes[agent.ID] = agent
		r.order = append(r.order, agent.ID)
		r.sources[agent.ID] = model.NodeSourceStatic
		r.staticIDs[agent.ID] = struct{}{}
		if !agent.IsEnabled() {
			r.health[agent.ID] = nodeHealth{status: HealthDisabled}
		} else {
			r.health[agent.ID] = nodeHealth{status: HealthUnknown}
		}
	}
	return r
}

// LoadRegisteredAgents attaches the persistent store and restores the Agents
// that enrolled themselves before this process started. Rows whose node id is
// now statically configured are ignored (static configuration wins) but kept in
// the database.
func (r *Registry) LoadRegisteredAgents(ctx context.Context, store *Store) error {
	if store == nil {
		return ErrRegistryHasNoStore
	}
	registered, err := store.ListRegisteredAgents(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.store = store
	for _, record := range registered {
		if _, collides := r.staticIDs[record.NodeID]; collides {
			r.logger.Warn("registered agent ignored because a static node uses the same id", "node_id", record.NodeID)
			continue
		}
		// Revalidate persisted state defensively: the database is trusted, but
		// a corrupted or hand-edited row must never become an arbitrary Agent.
		if model.ValidateNodeID(record.NodeID) != nil || record.AgentToken == "" {
			r.logger.Warn("registered agent row is invalid and was ignored", "node_id", record.NodeID)
			continue
		}
		if err := validateAgentURL(record.URL); err != nil {
			r.logger.Warn("registered agent url is invalid and was ignored", "node_id", record.NodeID)
			continue
		}
		record.Name = model.SanitizeText(record.Name, 64)
		if record.Name == "" {
			record.Name = record.NodeID
		}
		record.Location = model.SanitizeText(record.Location, 128)
		record.Provider = model.SanitizeText(record.Provider, 128)
		r.upsertAutoLocked(record, newAutoAgent(r.cfg, record))
	}
	return nil
}

// RegisterAuto persists a newly enrolled (or re-enrolled) Agent, updates the
// in-memory registry (static configuration always wins) and triggers an
// immediate health check. The caller must already have generated the trace
// token and validated the request.
func (r *Registry) RegisterAuto(ctx context.Context, record RegisteredAgent) (*AgentConfig, error) {
	r.mu.RLock()
	_, collides := r.staticIDs[record.NodeID]
	store := r.store
	r.mu.RUnlock()
	if collides {
		return nil, ErrStaticNodeCollision
	}
	if store == nil {
		return nil, ErrRegistryHasNoStore
	}
	if err := store.UpsertRegisteredAgent(ctx, record); err != nil {
		return nil, err
	}
	agent := newAutoAgent(r.cfg, record)
	r.mu.Lock()
	r.upsertAutoLocked(record, agent)
	r.mu.Unlock()
	r.checkAsync(agent)
	return agent, nil
}

func newAutoAgent(cfg *Config, record RegisteredAgent) *AgentConfig {
	enabled := true
	return &AgentConfig{
		ID:               record.NodeID,
		Name:             record.Name,
		Location:         record.Location,
		Provider:         record.Provider,
		URL:              record.URL,
		Enabled:          &enabled,
		RequestTimeoutMS: cfg.Limits.MaxExecutionMS + 15_000,
		token:            record.AgentToken,
	}
}

func (r *Registry) upsertAutoLocked(record RegisteredAgent, agent *AgentConfig) {
	if _, exists := r.nodes[record.NodeID]; !exists {
		r.order = append(r.order, record.NodeID)
		r.health[record.NodeID] = nodeHealth{status: HealthUnknown}
	}
	r.nodes[record.NodeID] = agent
	r.sources[record.NodeID] = model.NodeSourceAuto
}

// StaticNodeID reports whether id belongs to an administratively configured
// Agent. Enrollment must never override such a node.
func (r *Registry) StaticNodeID(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.staticIDs[id]
	return ok
}

// Source returns how a node entered the registry.
func (r *Registry) Source(id string) model.NodeSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sources[id]
}

// Get returns the configured or auto-enrolled Agent for id.
func (r *Registry) Get(id string) (*AgentConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	agent, ok := r.nodes[id]
	return agent, ok
}

// All returns all Agents (static first, then auto-enrollment order).
func (r *Registry) All() []*AgentConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*AgentConfig, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.nodes[id])
	}
	return out
}

// Health returns the cached health state for a node.
func (r *Registry) Health(id string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if h, ok := r.health[id]; ok {
		return h.status
	}
	return HealthUnknown
}

// NodeInfos returns the public node list. It never exposes URLs or tokens.
func (r *Registry) NodeInfos() []model.NodeInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.NodeInfo, 0, len(r.order))
	for _, id := range r.order {
		agent := r.nodes[id]
		health := r.health[id]
		info := model.NodeInfo{
			ID:       agent.ID,
			Name:     agent.Name,
			Location: agent.Location,
			Provider: agent.Provider,
			Enabled:  agent.IsEnabled(),
			Health:   health.status,
			Source:   r.sources[id],
		}
		if !health.lastSeen.IsZero() {
			info.LastSeen = health.lastSeen.UTC().Format(time.RFC3339)
			info.NextTraceVersion = health.nextTraceVersion
		}
		if len(health.interfaces) > 0 {
			info.Interfaces = append([]string(nil), health.interfaces...)
		}
		out = append(out, info)
	}
	return out
}

// CheckAll performs authenticated health checks for every enabled node with
// bounded concurrency and updates the cached status.
func (r *Registry) CheckAll(ctx context.Context) {
	const maxConcurrentChecks = 4
	sem := make(chan struct{}, maxConcurrentChecks)
	var wg sync.WaitGroup
	for _, agent := range r.All() {
		if !agent.IsEnabled() {
			continue
		}
		wg.Add(1)
		go func(agent *AgentConfig) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			r.checkOne(ctx, agent)
		}(agent)
	}
	wg.Wait()
}

func (r *Registry) checkAsync(agent *AgentConfig) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*healthTimeout)
		defer cancel()
		r.checkOne(ctx, agent)
	}()
}

func (r *Registry) checkOne(ctx context.Context, agent *AgentConfig) {
	health, err := r.client.Health(ctx, agent)
	now := r.now().UTC()
	r.mu.Lock()
	if err != nil {
		current := r.health[agent.ID]
		current.status = HealthUnreachable
		r.health[agent.ID] = current
		r.mu.Unlock()
		r.logger.Warn("agent health check failed", "node_id", agent.ID, "error", err.Error())
		return
	}
	status := HealthOK
	if health.Status != "ok" || !health.NextTrace.Available {
		status = HealthDegraded
	}
	source := r.sources[agent.ID]
	store := r.store
	r.health[agent.ID] = nodeHealth{
		status:           status,
		lastSeen:         now,
		nextTraceVersion: model.SanitizeText(health.NextTrace.Version, 64),
		interfaces:       sanitizeAdvertisedInterfaces(health.Interfaces),
	}
	r.mu.Unlock()

	if source == model.NodeSourceAuto && store != nil {
		touchCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := store.TouchRegisteredAgentLastSeen(touchCtx, agent.ID, now); err != nil {
			r.logger.Debug("could not record registered agent last seen", "node_id", agent.ID)
		}
		cancel()
	}
}

// Interfaces returns a copy of the interfaces the Agent advertised in its last
// successful health check. An empty slice means the Agent advertised none (or
// has not been reachable yet).
func (r *Registry) Interfaces(id string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	health, ok := r.health[id]
	if !ok || len(health.interfaces) == 0 {
		return nil
	}
	return append([]string(nil), health.interfaces...)
}

// sanitizeAdvertisedInterfaces keeps only syntactically valid interface names,
// removes duplicates and preserves the Agent's ordering. The advertisement is
// untrusted input even though the Agent is authenticated: it is never passed
// through as an opaque string.
func sanitizeAdvertisedInterfaces(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		if len(out) >= maxAdvertisedInterfaces {
			break
		}
		if name == "" || model.ValidateInterfaceName(name) != nil {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Start runs the background health poller until ctx is cancelled. It checks
// immediately and then every interval.
func (r *Registry) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.CheckAll(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.CheckAll(ctx)
			}
		}
	}()
}

// Wait blocks until the background poller and any in-flight enrollment health
// checks have stopped.
func (r *Registry) Wait() { r.wg.Wait() }
