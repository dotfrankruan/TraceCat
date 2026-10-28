package controller

import (
	"context"
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

type nodeHealth struct {
	status           string
	lastSeen         time.Time
	nextTraceVersion string
}

// Registry is the administrative node table. Nodes come exclusively from the
// validated configuration; there is no runtime registration API.
type Registry struct {
	cfg    *Config
	client *AgentClient
	logger *slog.Logger
	now    func() time.Time

	mu     sync.RWMutex
	nodes  map[string]*AgentConfig
	order  []string
	health map[string]nodeHealth

	wg sync.WaitGroup
}

// NewRegistry builds the node registry.
func NewRegistry(cfg *Config, client *AgentClient, logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	r := &Registry{
		cfg:    cfg,
		client: client,
		logger: logger,
		now:    time.Now,
		nodes:  make(map[string]*AgentConfig, len(cfg.Agents)),
		order:  make([]string, 0, len(cfg.Agents)),
		health: make(map[string]nodeHealth, len(cfg.Agents)),
	}
	for i := range cfg.Agents {
		agent := &cfg.Agents[i]
		r.nodes[agent.ID] = agent
		r.order = append(r.order, agent.ID)
		if !agent.IsEnabled() {
			r.health[agent.ID] = nodeHealth{status: HealthDisabled}
		} else {
			r.health[agent.ID] = nodeHealth{status: HealthUnknown}
		}
	}
	return r
}

// Get returns the configured Agent for id.
func (r *Registry) Get(id string) (*AgentConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	agent, ok := r.nodes[id]
	return agent, ok
}

// All returns configured Agents in configuration order.
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
		}
		if !health.lastSeen.IsZero() {
			info.LastSeen = health.lastSeen.UTC().Format(time.RFC3339)
			info.NextTraceVersion = health.nextTraceVersion
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

func (r *Registry) checkOne(ctx context.Context, agent *AgentConfig) {
	health, err := r.client.Health(ctx, agent)
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		current := r.health[agent.ID]
		current.status = HealthUnreachable
		r.health[agent.ID] = current
		r.logger.Warn("agent health check failed", "node_id", agent.ID)
		return
	}
	status := HealthOK
	if health.Status != "ok" || !health.NextTrace.Available {
		status = HealthDegraded
	}
	r.health[agent.ID] = nodeHealth{
		status:           status,
		lastSeen:         now,
		nextTraceVersion: model.SanitizeText(health.NextTrace.Version, 64),
	}
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

// Wait blocks until the background poller has stopped.
func (r *Registry) Wait() { r.wg.Wait() }
