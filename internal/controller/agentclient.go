package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	defaultMaxAgentResponseBytes = 16 << 20 // 16 MiB, per the Agent response contract.
	healthMaxResponseBytes       = 64 << 10
	healthTimeout                = 5 * time.Second
)

// agentErrorKind classifies Controller->Agent failures so the job manager can
// map them onto per-node statuses without parsing error strings.
type agentErrorKind int

const (
	agentErrUnreachable agentErrorKind = iota
	agentErrProtocol
	agentErrTimeout
	agentErrCancelled
	agentErrTooLarge
)

type agentCallError struct {
	kind       agentErrorKind
	statusCode int
	code       model.ErrorCode
	message    string
}

func (e *agentCallError) Error() string { return e.message }

func newAgentCallError(kind agentErrorKind, code model.ErrorCode, message string) *agentCallError {
	return &agentCallError{kind: kind, code: code, message: message}
}

// AgentClient talks to administratively configured Agents. It never accepts a
// URL from a request. Redirects are never followed and response bodies are
// strictly bounded.
type AgentClient struct {
	httpClient       *http.Client
	maxResponseBytes int64
}

// AgentClientOption customizes the Agent client.
type AgentClientOption func(*AgentClient)

// WithAgentHTTPClient injects the HTTP client.
func WithAgentHTTPClient(client *http.Client) AgentClientOption {
	return func(c *AgentClient) { c.httpClient = client }
}

// WithAgentMaxResponseBytes bounds Agent response bodies (tests use a small
// value instead of allocating 16 MiB).
func WithAgentMaxResponseBytes(n int64) AgentClientOption {
	return func(c *AgentClient) { c.maxResponseBytes = n }
}

// NewAgentClient builds a client with the production transport defaults.
func NewAgentClient(opts ...AgentClientOption) *AgentClient {
	transport := &http.Transport{
		Proxy:                 nil, // Agents are only reachable over the private network.
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	c := &AgentClient{
		httpClient: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxResponseBytes: defaultMaxAgentResponseBytes,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *AgentClient) newRequest(ctx context.Context, node *AgentConfig, method, path string, body []byte) (*http.Request, error) {
	endpoint := node.BaseURL() + path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, newAgentCallError(agentErrUnreachable, ErrAgentError, "agent endpoint is invalid")
	}
	req.Header.Set("Authorization", "Bearer "+node.Token())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// Health performs the authenticated Agent health check.
func (c *AgentClient) Health(ctx context.Context, node *AgentConfig) (*model.AgentHealth, error) {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	req, err := c.newRequest(ctx, node, http.MethodGet, "/v1/health", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, newAgentCallError(agentErrUnreachable, model.ErrAgentUnreachable, "agent unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, newAgentCallError(agentErrProtocol, model.ErrAgentUnreachable, "agent health check failed")
	}
	body, err := readLimited(resp.Body, healthMaxResponseBytes)
	if err != nil {
		return nil, newAgentCallError(agentErrProtocol, model.ErrAgentUnreachable, "agent health response is invalid")
	}
	var health model.AgentHealth
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, newAgentCallError(agentErrProtocol, model.ErrAgentUnreachable, "agent health response is invalid")
	}
	if health.SchemaVersion != model.AgentSchemaVersion || health.NodeID != node.ID {
		return nil, newAgentCallError(agentErrProtocol, model.ErrAgentUnreachable, "agent health response does not match the node")
	}
	return &health, nil
}

// Trace dispatches one trace request to an Agent and validates the response
// envelope. It returns the parsed response (including raw output) on success.
func (c *AgentClient) Trace(ctx context.Context, node *AgentConfig, traceReq *model.AgentTraceRequest, timeout time.Duration) (*model.AgentTraceResponse, error) {
	body, err := json.Marshal(traceReq)
	if err != nil {
		return nil, newAgentCallError(agentErrProtocol, model.ErrInternal, "could not encode trace request")
	}
	if timeout <= 0 {
		timeout = time.Duration(traceReq.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := c.newRequest(ctx, node, http.MethodPost, "/v1/trace", body)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return nil, newAgentCallError(agentErrTimeout, model.ErrTimeout, "agent request timed out")
		case errors.Is(ctx.Err(), context.Canceled):
			return nil, newAgentCallError(agentErrCancelled, model.ErrCancelled, "agent request cancelled")
		default:
			return nil, newAgentCallError(agentErrUnreachable, model.ErrAgentUnreachable, "agent unreachable")
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain a small amount so the connection can be reused, then classify.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return nil, newAgentCallError(agentErrProtocol, ErrAgentError, "agent rejected the Controller credentials")
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
			return nil, newAgentCallError(agentErrProtocol, ErrAgentError, fmt.Sprintf("agent is busy (status %d)", resp.StatusCode))
		case resp.StatusCode >= 500:
			return nil, newAgentCallError(agentErrUnreachable, model.ErrAgentUnreachable, fmt.Sprintf("agent failed (status %d)", resp.StatusCode))
		default:
			return nil, newAgentCallError(agentErrProtocol, ErrAgentError, fmt.Sprintf("agent rejected the request (status %d)", resp.StatusCode))
		}
	}

	raw, err := readLimited(resp.Body, c.maxResponseBytes)
	if err != nil {
		return nil, newAgentCallError(agentErrTooLarge, ErrAgentError, "agent response is too large")
	}
	var traceResp model.AgentTraceResponse
	if err := json.Unmarshal(raw, &traceResp); err != nil {
		return nil, newAgentCallError(agentErrProtocol, model.ErrParseError, "agent returned an invalid response")
	}
	if err := validateAgentTraceResponse(&traceResp, traceReq); err != nil {
		return nil, err
	}
	return &traceResp, nil
}

// ErrAgentError is the stable Controller-side code for a well-formed but
// unusable Agent response/status. It complements model.model.ErrAgentUnreachable.
const ErrAgentError model.ErrorCode = "agent_error"

func validateAgentTraceResponse(resp *model.AgentTraceResponse, req *model.AgentTraceRequest) error {
	if resp.SchemaVersion != model.AgentSchemaVersion {
		return newAgentCallError(agentErrProtocol, model.ErrUnsupportedVersion, "agent returned an unsupported schema version")
	}
	if resp.JobID != req.JobID || resp.NodeID != req.NodeID {
		return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response does not match the request")
	}
	if !resp.Status.Valid() || !resp.Status.Terminal() {
		return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response has an invalid status")
	}
	if resp.TargetIP != "" {
		addr, err := ipguard.NormalizeIP(resp.TargetIP)
		if err != nil || addr.String() != req.TargetIP {
			return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response target does not match the request")
		}
	}
	if resp.Family != "" && resp.Family != req.Family {
		return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response family does not match the request")
	}
	if !resp.Protocol.Valid() || resp.Protocol != req.Protocol {
		return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response protocol does not match the request")
	}
	if err := model.ValidatePortForProtocol(resp.Protocol, resp.Port); err != nil {
		return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response port does not match the request")
	}
	if req.Protocol.RequiresPort() {
		if resp.Port == nil || req.Port == nil || *resp.Port != *req.Port {
			return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response port does not match the request")
		}
	} else if resp.Port != nil {
		return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response must omit port for icmp")
	}
	if err := model.ValidateInterfaceName(resp.Interface); err != nil {
		return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response interface is invalid")
	}
	if resp.Interface != req.Interface {
		return newAgentCallError(agentErrProtocol, model.ErrParseError, "agent response interface does not match the request")
	}
	return nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, errors.New("response too large")
	}
	return body, nil
}
