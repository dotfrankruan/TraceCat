package model

import "encoding/json"

// Session is returned by GET /api/v1/session. It is the only endpoint the
// frontend uses to discover the active authentication mode and server-side
// limits, so no such values need to be embedded in the compiled bundle.
type Session struct {
	Authenticated bool             `json:"authenticated"`
	Mode          string           `json:"mode"` // "dev", "local" or "cloudflare"
	User          *User            `json:"user,omitempty"`
	CSRFToken     string           `json:"csrf_token,omitempty"`
	Limits        ControllerLimits `json:"limits"`
	Version       string           `json:"version"`
	Warnings      []string         `json:"warnings,omitempty"`
}

// User identifies the authenticated principal when known.
type User struct {
	Email      string `json:"email,omitempty"`
	Subject    string `json:"subject,omitempty"`
	AuthMethod string `json:"auth_method,omitempty"` // "dev", "local" or "cloudflare"
}

// ControllerLimits is the server-side allowlist of numeric trace limits.
type ControllerLimits struct {
	MaxHops        int      `json:"max_hops"`
	MaxQueries     int      `json:"max_queries"`
	MaxExecutionMS int      `json:"max_execution_ms"`
	MinExecutionMS int      `json:"min_execution_ms"`
	MaxNodesPerJob int      `json:"max_nodes_per_job"`
	MaxAddresses   int      `json:"max_addresses"`
	MaxHistoryJobs int      `json:"max_history_jobs"`
	Protocols      []string `json:"protocols"`
}

// LoginRequest is the local-auth login body. Only used when auth.mode=local.
type LoginRequest struct {
	Password string `json:"password"`
}

// ResolveRequest is the body of POST /api/v1/resolve. The input is either an
// IP literal or a domain (IDN allowed); it is never a URL or shell fragment.
type ResolveRequest struct {
	Target string `json:"target"`
}

// ResolvedAddress is one selectable numeric destination returned to the user.
type ResolvedAddress struct {
	IP     string   `json:"ip"`
	Family IPFamily `json:"family"`
}

// ResolveResponse is the body of a successful POST /api/v1/resolve. When more
// than one address is returned the frontend must require an explicit choice.
type ResolveResponse struct {
	Input             string            `json:"input"`
	Kind              string            `json:"kind"` // "ip" or "domain"
	Addresses         []ResolvedAddress `json:"addresses"`
	RequiresSelection bool              `json:"requires_selection"`
	Truncated         bool              `json:"truncated"`
	Warnings          []string          `json:"warnings,omitempty"`
}

// NodeInfo is the administrative, non-secret description of an Agent.
type NodeInfo struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Location         string   `json:"location,omitempty"`
	Provider         string   `json:"provider,omitempty"`
	Enabled          bool     `json:"enabled"`
	Health           string   `json:"health"` // "ok", "unreachable", "degraded", "unknown", "disabled"
	LastSeen         string   `json:"last_seen,omitempty"`
	NextTraceVersion string   `json:"nexttrace_version,omitempty"`
	Interfaces       []string `json:"interfaces,omitempty"`
}

// NodeList is returned by GET /api/v1/nodes.
type NodeList struct {
	Nodes []NodeInfo `json:"nodes"`
}

// CreateJobRequest is the body of POST /api/v1/jobs. target_ip must be one of
// the numeric addresses previously returned by /resolve; original_target is
// stored only by the Controller for display.
type CreateJobRequest struct {
	TargetIP       string   `json:"target_ip"`
	OriginalTarget string   `json:"original_target"`
	NodeIDs        []string `json:"node_ids"`
	Protocol       Protocol `json:"protocol"`
	// Port is required for tcp/udp and must be omitted for icmp.
	Port *int `json:"port,omitempty"`
	// NodeInterfaces optionally selects a source network interface per node
	// (node id -> interface name). Omitted/empty means automatic routing. Each
	// name is validated against that Agent's advertised interface list.
	NodeInterfaces map[string]string `json:"node_interfaces,omitempty"`
	MaxHops        int               `json:"max_hops"`
	Queries        int               `json:"queries"`
	TimeoutMS      int               `json:"timeout_ms"`
}

// Job is the full distributed trace job returned by the Controller API.
type Job struct {
	SchemaVersion  string       `json:"schema_version"`
	ID             string       `json:"id"`
	Status         JobStatus    `json:"status"`
	TargetIP       string       `json:"target_ip"`
	OriginalTarget string       `json:"original_target"`
	Family         IPFamily     `json:"family"`
	Protocol       Protocol     `json:"protocol"`
	Port           *int         `json:"port,omitempty"`
	MaxHops        int          `json:"max_hops"`
	Queries        int          `json:"queries"`
	TimeoutMS      int          `json:"timeout_ms"`
	CreatedAt      string       `json:"created_at"`
	StartedAt      string       `json:"started_at,omitempty"`
	EndedAt        string       `json:"ended_at,omitempty"`
	CreatedBy      string       `json:"created_by,omitempty"`
	Nodes          []NodeResult `json:"nodes"`
	Summary        JobSummary   `json:"summary"`
}

// JobSummary aggregates per-node states so the UI can render progress without
// recomputing it.
type JobSummary struct {
	Total     int `json:"total"`
	Pending   int `json:"pending"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	TimedOut  int `json:"timed_out"`
	Cancelled int `json:"cancelled"`
	Reached   int `json:"reached"`
}

// SummarizeJob recomputes JobSummary from node results.
func SummarizeJob(nodes []NodeResult) JobSummary {
	var s JobSummary
	s.Total = len(nodes)
	for _, n := range nodes {
		switch n.Status {
		case NodePending:
			s.Pending++
		case NodeRunning:
			s.Running++
		case NodeCompleted:
			s.Completed++
		case NodeFailed:
			s.Failed++
		case NodeTimedOut:
			s.TimedOut++
		case NodeCancelled:
			s.Cancelled++
		}
		if n.Summary != nil && n.Summary.ReachedDestination {
			s.Reached++
		}
	}
	return s
}

// JobListItem is a bounded history entry (no hops) returned by GET /api/v1/jobs.
type JobListItem struct {
	ID             string     `json:"id"`
	Status         JobStatus  `json:"status"`
	TargetIP       string     `json:"target_ip"`
	OriginalTarget string     `json:"original_target"`
	Family         IPFamily   `json:"family"`
	Protocol       Protocol   `json:"protocol"`
	Port           *int       `json:"port,omitempty"`
	CreatedAt      string     `json:"created_at"`
	EndedAt        string     `json:"ended_at,omitempty"`
	Summary        JobSummary `json:"summary"`
}

// JobList is returned by GET /api/v1/jobs.
type JobList struct {
	Jobs []JobListItem `json:"jobs"`
}

// JobResponse envelopes a single job.
type JobResponse struct {
	Job Job `json:"job"`
}

// JobExport is the downloadable structured JSON representation of a job. Raw
// NextTrace outputs are included only here, never in the interactive API.
type JobExport struct {
	SchemaVersion string                     `json:"schema_version"`
	ExportedAt    string                     `json:"exported_at"`
	Job           Job                        `json:"job"`
	RawResults    map[string]json.RawMessage `json:"raw_results,omitempty"`
}

// SSE event names emitted by GET /api/v1/jobs/{id}/events. The payload of each
// event is the complete Job document so a reconnecting client can recover
// without extra state.
const (
	SSEEventJob = "job"
)
