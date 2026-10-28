package agent

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
	"github.com/dotfrankruan/tracecat/internal/nexttrace"
)

// traceOutcome is the internal result of one NextTrace execution, already
// mapped onto the Agent wire contract.
type traceOutcome struct {
	status       model.NodeStatus
	err          *model.APIError
	hops         []model.Hop
	summary      model.TraceSummary
	parserSchema string
	raw          json.RawMessage
	rawTruncated bool
}

// executeTrace runs one traceroute and maps every failure mode onto a terminal
// node status plus a stable error code. Trace-internal failures still result in
// HTTP 200; only malformed or unauthorized requests are rejected at the HTTP
// layer.
func (a *Agent) executeTrace(ctx context.Context, req *model.AgentTraceRequest, target netip.Addr) traceOutcome {
	if !a.caps.Available() {
		message := "nexttrace is not available"
		if a.info.Error != nil && a.info.Error.Message != "" {
			message = a.info.Error.Message
		}
		return traceOutcome{
			status: model.NodeFailed,
			err:    model.NewError(model.ErrNextTraceMissing, message),
		}
	}

	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if limit := time.Duration(a.cfg.NextTrace.MaxExecutionMS) * time.Millisecond; timeout > limit {
		timeout = limit
	}
	spec := nexttrace.Spec{
		Addr:           target,
		Family:         req.Family,
		Protocol:       req.Protocol,
		MaxHops:        req.MaxHops,
		Queries:        req.Queries,
		ProbeTimeoutMS: a.cfg.NextTrace.ProbeTimeoutMS,
	}

	result, runErr := a.runner.Run(ctx, spec, timeout, nexttrace.RunLimits{
		MaxStdoutBytes: a.cfg.NextTrace.MaxStdoutBytes,
		MaxStderrBytes: nexttrace.DefaultMaxStderrBytes,
	})
	if runErr != nil {
		status := model.NodeFailed
		switch runErr.Code {
		case model.ErrTimeout:
			status = model.NodeTimedOut
		case model.ErrCancelled:
			status = model.NodeCancelled
		}
		return traceOutcome{status: status, err: runErr}
	}

	parsed, parseErr := nexttrace.Parse(result.Stdout, nexttrace.ParseOptions{
		TargetIP:    target.String(),
		MaxRawBytes: int(a.cfg.NextTrace.MaxRawBytes),
	})
	if parseErr != nil {
		return traceOutcome{status: model.NodeFailed, err: parseErr}
	}

	return traceOutcome{
		status:       model.NodeCompleted,
		hops:         parsed.Hops,
		summary:      parsed.Summary,
		parserSchema: model.NextTraceJSONSchema,
		raw:          parsed.RawResult,
		rawTruncated: parsed.RawResultTruncated,
	}
}
