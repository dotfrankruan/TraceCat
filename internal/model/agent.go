package model

import (
	"encoding/json"
	"fmt"
)

// AgentTraceRequest is the exact body accepted by POST /v1/trace on an Agent.
// The Agent decodes it with unknown-field rejection and revalidates every
// field independently of the Controller.
type AgentTraceRequest struct {
	SchemaVersion string   `json:"schema_version"`
	JobID         string   `json:"job_id"`
	NodeID        string   `json:"node_id"`
	TargetIP      string   `json:"target_ip"`
	Family        IPFamily `json:"family"`
	Protocol      Protocol `json:"protocol"`
	MaxHops       int      `json:"max_hops"`
	Queries       int      `json:"queries"`
	TimeoutMS     int      `json:"timeout_ms"`
	// Port is the destination port for tcp/udp probes and must be omitted for
	// icmp. It is always a bounded integer validated by both sides.
	Port *int `json:"port,omitempty"`
	// Interface optionally selects one of the Agent's enumerated network
	// interfaces (NextTrace -D/--dev). Empty means "automatic routing". The
	// Agent revalidates the name against its own allowlisted interface set.
	Interface string `json:"interface,omitempty"`
}

// NextTraceInfo describes the locally installed NextTrace binary as detected at
// Agent startup. It never exposes the executable path or environment.
type NextTraceInfo struct {
	Available    bool      `json:"available"`
	Version      string    `json:"version,omitempty"`
	Capabilities []string  `json:"capabilities,omitempty"`
	Error        *APIError `json:"error,omitempty"`
}

// AgentLimits advertises the hard limits the Agent enforces.
type AgentLimits struct {
	MaxHops             int      `json:"max_hops"`
	MaxQueries          int      `json:"max_queries"`
	MaxTimeoutMS        int      `json:"max_timeout_ms"`
	MaxConcurrentTraces int      `json:"max_concurrent_traces"`
	Protocols           []string `json:"protocols"`
}

// AgentHealth is the authenticated response of GET /v1/health.
type AgentHealth struct {
	SchemaVersion string        `json:"schema_version"`
	Status        string        `json:"status"` // "ok" or "degraded"
	NodeID        string        `json:"node_id"`
	Version       string        `json:"version"`
	NextTrace     NextTraceInfo `json:"nexttrace"`
	Limits        AgentLimits   `json:"limits"`
	Time          string        `json:"time"`
}

// AgentTraceResponse is the response of POST /v1/trace. A trace that ran but
// produced no usable output is returned with Status failed and Error set; HTTP
// 200 is still used because the Agent itself handled the request correctly.
type AgentTraceResponse struct {
	SchemaVersion    string       `json:"schema_version"`
	JobID            string       `json:"job_id"`
	NodeID           string       `json:"node_id"`
	Status           NodeStatus   `json:"status"`
	TargetIP         string       `json:"target_ip"`
	Family           IPFamily     `json:"family"`
	Protocol         Protocol     `json:"protocol"`
	Port             *int         `json:"port,omitempty"`
	Interface        string       `json:"interface,omitempty"`
	StartedAt        string       `json:"started_at"`
	EndedAt          string       `json:"ended_at"`
	DurationMS       int64        `json:"duration_ms"`
	NextTraceVersion string       `json:"nexttrace_version,omitempty"`
	ParserSchema     string       `json:"parser_schema,omitempty"`
	Summary          TraceSummary `json:"summary"`
	Hops             []Hop        `json:"hops,omitempty"`
	Error            *APIError    `json:"error,omitempty"`
	// RawResult is the bounded, unmodified structured NextTrace output retained
	// for debugging. It is omitted when the Agent did not obtain parseable JSON
	// or when it exceeded the configured raw-output limit.
	RawResult          json.RawMessage `json:"raw_result,omitempty"`
	RawResultTruncated bool            `json:"raw_result_truncated,omitempty"`
}

// ErrorResponse is the JSON envelope used for every HTTP error by both
// Controller and Agent.
type ErrorResponse struct {
	Error *APIError `json:"error"`
}

// Err constructs an ErrorResponse.
func Err(code ErrorCode, msg string) ErrorResponse {
	return ErrorResponse{Error: NewError(code, msg)}
}

// Validate performs structural validation of an Agent trace request that does
// not require local policy (IP policy is enforced by ipguard in the Agent).
func (r *AgentTraceRequest) Validate() error {
	if r.SchemaVersion != AgentSchemaVersion {
		return NewError(ErrUnsupportedVersion, "unsupported schema_version")
	}
	if err := ValidateJobID(r.JobID); err != nil {
		return err
	}
	if err := ValidateNodeID(r.NodeID); err != nil {
		return err
	}
	if !r.Family.Valid() {
		return NewError(ErrInvalidRequest, "invalid family")
	}
	if !r.Protocol.Valid() {
		return NewError(ErrInvalidRequest, "invalid protocol")
	}
	if err := ValidatePortForProtocol(r.Protocol, r.Port); err != nil {
		return err
	}
	if err := ValidateInterfaceName(r.Interface); err != nil {
		return err
	}
	return ValidateLimits(r.MaxHops, r.Queries, r.TimeoutMS)
}

// String is used only in debug logs; it deliberately omits nothing sensitive
// because the request contains no secrets.
func (r *AgentTraceRequest) String() string {
	port := ""
	if r.Port != nil {
		port = fmt.Sprintf(" port=%d", *r.Port)
	}
	return fmt.Sprintf("job=%s node=%s target=%s family=%s protocol=%s%s hops=%d queries=%d timeout_ms=%d",
		r.JobID, r.NodeID, r.TargetIP, r.Family, r.Protocol, port, r.MaxHops, r.Queries, r.TimeoutMS)
}
