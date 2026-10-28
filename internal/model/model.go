// Package model defines the versioned wire contract shared by the TraceCat
// Controller and Agents. It is deliberately free of business logic: it holds
// enums, validated types, limits and the exact JSON shapes exposed by the
// versioned APIs. It must not import any other TraceCat package.
package model

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Schema versions are part of the wire contract. Bump the major component when
// an incompatible change is made; both sides reject unknown versions.
const (
	// AgentSchemaVersion is the schema for Controller <-> Agent traffic.
	AgentSchemaVersion = "tracecat.agent.v1"
	// ControllerSchemaVersion is the schema for Browser <-> Controller traffic.
	ControllerSchemaVersion = "tracecat.controller.v1"
	// NextTraceJSONSchema identifies the normalized NextTrace JSON dialect the
	// Agent parser emits. It is independent of the NextTrace binary version.
	NextTraceJSONSchema = "nexttrace.json.v1"
)

// Hard bounds shared by Controller and Agent. These are defense-in-depth
// limits: both sides validate independently.
const (
	MinMaxHops = 1
	MaxMaxHops = 64

	MinQueries = 1
	MaxQueries = 5

	MinExecutionTimeoutMS = 5_000
	MaxExecutionTimeoutMS = 120_000

	MaxJobIDLen          = 64
	MaxNodeIDLen         = 32
	MaxOriginalTargetLen = 253
	// MaxInterfaceNameLen is the Linux IFNAMSIZ upper bound (15 visible bytes).
	MaxInterfaceNameLen = 15
	MaxLabelRunes       = 128

	// MaxBatchNodes is the absolute number of Agents a single job may target.
	MaxBatchNodes = 16

	// MinPort and MaxPort bound the destination port for TCP/UDP probes.
	MinPort = 1
	MaxPort = 65535

	// DefaultTCPPort and DefaultUDPPort are the conventional probe ports used
	// by NextTrace when none is specified; the Controller/UI preselect them but
	// the user may choose any bounded port.
	DefaultTCPPort = 80
	DefaultUDPPort = 33494
)

// IPFamily is the normalized address family of a target.
type IPFamily string

const (
	FamilyIPv4 IPFamily = "ipv4"
	FamilyIPv6 IPFamily = "ipv6"
)

// Valid reports whether f is a known family.
func (f IPFamily) Valid() bool { return f == FamilyIPv4 || f == FamilyIPv6 }

// FamilyOf returns the family of addr. addr must be normalized (see
// netip.Addr.Unmap); an IPv4-mapped IPv6 address is reported as IPv4.
func FamilyOf(addr netip.Addr) IPFamily {
	if addr.Unmap().Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// Protocol is the traceroute probe protocol. Only the fixed enum values are
// accepted: the Agent maps each one to a capability-detected NextTrace flag and
// never accepts arbitrary flags or protocols from a caller. MTR sessions are
// not part of the contract.
type Protocol string

const (
	ProtocolICMP Protocol = "icmp"
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
)

// Valid reports whether p is an enabled protocol.
func (p Protocol) Valid() bool {
	switch p {
	case ProtocolICMP, ProtocolTCP, ProtocolUDP:
		return true
	default:
		return false
	}
}

// RequiresPort reports whether p probes a destination port. ICMP does not; TCP
// and UDP require an explicit bounded port.
func (p Protocol) RequiresPort() bool {
	return p == ProtocolTCP || p == ProtocolUDP
}

// DefaultPort returns the conventional probe port for p, when applicable.
func (p Protocol) DefaultPort() (int, bool) {
	switch p {
	case ProtocolTCP:
		return DefaultTCPPort, true
	case ProtocolUDP:
		return DefaultUDPPort, true
	default:
		return 0, false
	}
}

// ValidatePortForProtocol enforces the exact protocol/port contract: ICMP must
// not carry a port, while TCP/UDP must carry one in [MinPort, MaxPort].
func ValidatePortForProtocol(protocol Protocol, port *int) error {
	if !protocol.Valid() {
		return NewError(ErrInvalidRequest, "invalid protocol")
	}
	if !protocol.RequiresPort() {
		if port != nil {
			return NewError(ErrInvalidRequest, "port must not be set for icmp")
		}
		return nil
	}
	if port == nil {
		return NewError(ErrInvalidRequest, fmt.Sprintf("port is required for %s", protocol))
	}
	if *port < MinPort || *port > MaxPort {
		return NewError(ErrInvalidRequest, fmt.Sprintf("port must be between %d and %d", MinPort, MaxPort))
	}
	return nil
}

// ParseProtocolList validates and normalizes an administrator-configured
// protocol allowlist. Empty input is an error; duplicates are rejected so
// configuration mistakes are visible at startup rather than silently ignored.
func ParseProtocolList(entries []string) ([]Protocol, error) {
	if len(entries) == 0 {
		return nil, NewError(ErrInvalidRequest, "at least one protocol must be enabled")
	}
	seen := make(map[Protocol]struct{}, len(entries))
	out := make([]Protocol, 0, len(entries))
	for _, raw := range entries {
		name := Protocol(strings.ToLower(strings.TrimSpace(raw)))
		if !name.Valid() {
			return nil, NewError(ErrInvalidRequest, fmt.Sprintf("unsupported protocol %q", raw))
		}
		if _, dup := seen[name]; dup {
			return nil, NewError(ErrInvalidRequest, fmt.Sprintf("duplicate protocol %q", raw))
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

// ProtocolNames converts protocols to their wire names, preserving order.
func ProtocolNames(protocols []Protocol) []string {
	out := make([]string, len(protocols))
	for i, p := range protocols {
		out[i] = string(p)
	}
	return out
}

// NodeStatus is the execution state of one Agent inside one distributed job.
type NodeStatus string

const (
	NodePending   NodeStatus = "pending"
	NodeRunning   NodeStatus = "running"
	NodeCompleted NodeStatus = "completed"
	NodeFailed    NodeStatus = "failed"
	NodeTimedOut  NodeStatus = "timed_out"
	NodeCancelled NodeStatus = "cancelled"
)

// Terminal reports whether no further transition is expected.
func (s NodeStatus) Terminal() bool {
	switch s {
	case NodeCompleted, NodeFailed, NodeTimedOut, NodeCancelled:
		return true
	default:
		return false
	}
}

// Valid reports whether s is a known node status.
func (s NodeStatus) Valid() bool {
	switch s {
	case NodePending, NodeRunning, NodeCompleted, NodeFailed, NodeTimedOut, NodeCancelled:
		return true
	default:
		return false
	}
}

// JobStatus is the aggregate state of a distributed trace job.
type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobPartial   JobStatus = "partial"
	JobFailed    JobStatus = "failed"
	JobCancelled JobStatus = "cancelled"
)

// Valid reports whether s is a known job status.
func (s JobStatus) Valid() bool {
	switch s {
	case JobPending, JobRunning, JobCompleted, JobPartial, JobFailed, JobCancelled:
		return true
	default:
		return false
	}
}

// ErrorCode is a stable, machine-readable error identifier. Messages are
// human-oriented and must never contain secrets, stack traces, environment
// variables or internal filesystem paths.
type ErrorCode string

const (
	ErrInvalidRequest     ErrorCode = "invalid_request"
	ErrUnauthorized       ErrorCode = "unauthorized"
	ErrForbidden          ErrorCode = "forbidden"
	ErrTargetRejected     ErrorCode = "target_rejected"
	ErrAgentUnreachable   ErrorCode = "agent_unreachable"
	ErrAgentError         ErrorCode = "agent_error"
	ErrNextTraceMissing   ErrorCode = "nexttrace_unavailable"
	ErrNextTraceFailed    ErrorCode = "nexttrace_failed"
	ErrParseError         ErrorCode = "parse_error"
	ErrTimeout            ErrorCode = "timeout"
	ErrCancelled          ErrorCode = "cancelled"
	ErrOutputTooLarge     ErrorCode = "output_too_large"
	ErrRateLimited        ErrorCode = "rate_limited"
	ErrBusy               ErrorCode = "busy"
	ErrNotFound           ErrorCode = "not_found"
	ErrConflict           ErrorCode = "conflict"
	ErrDNSError           ErrorCode = "dns_failure"
	ErrNoAddresses        ErrorCode = "no_addresses"
	ErrCSRFFailed         ErrorCode = "csrf_failed"
	ErrPayloadTooLarge    ErrorCode = "payload_too_large"
	ErrUnsupportedVersion ErrorCode = "unsupported_schema_version"
	ErrInternal           ErrorCode = "internal"
)

// APIError is the only error shape exposed on the wire.
type APIError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewError builds an APIError with a sanitized message.
func NewError(code ErrorCode, message string) *APIError {
	return &APIError{Code: code, Message: SanitizeText(message, 512)}
}

var (
	jobIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{15,63}$`)
	nodeIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	interfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)
)

// ValidateInterfaceName validates an Agent network-interface name before it is
// used as a typed NextTrace argument. It is only a syntactic check: callers
// must additionally verify that the name exists in the Agent's enumerated,
// allowlisted interface set. Empty means "let NextTrace choose the route".
func ValidateInterfaceName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > MaxInterfaceNameLen || !interfacePattern.MatchString(name) {
		return NewError(ErrInvalidRequest, "invalid interface name")
	}
	return nil
}

// ValidateJobID checks the opaque job identifier carried across the Agent API.
// TraceCat generates 32 lowercase hex characters, but the pattern is kept
// slightly wider to permit client-generated ids in tests.
func ValidateJobID(id string) error {
	if len(id) == 0 || len(id) > MaxJobIDLen || !jobIDPattern.MatchString(id) {
		return NewError(ErrInvalidRequest, "invalid job_id")
	}
	return nil
}

// ValidateNodeID checks an administratively configured node identifier.
func ValidateNodeID(id string) error {
	if len(id) == 0 || len(id) > MaxNodeIDLen || !nodeIDPattern.MatchString(id) {
		return NewError(ErrInvalidRequest, "invalid node_id")
	}
	return nil
}

// ValidateLimits validates user-controlled numeric trace limits. Both the
// Controller and the Agent call this independently.
func ValidateLimits(maxHops, queries, timeoutMS int) error {
	if maxHops < MinMaxHops || maxHops > MaxMaxHops {
		return NewError(ErrInvalidRequest, fmt.Sprintf("max_hops must be between %d and %d", MinMaxHops, MaxMaxHops))
	}
	if queries < MinQueries || queries > MaxQueries {
		return NewError(ErrInvalidRequest, fmt.Sprintf("queries must be between %d and %d", MinQueries, MaxQueries))
	}
	if timeoutMS < MinExecutionTimeoutMS || timeoutMS > MaxExecutionTimeoutMS {
		return NewError(ErrInvalidRequest, fmt.Sprintf("timeout_ms must be between %d and %d", MinExecutionTimeoutMS, MaxExecutionTimeoutMS))
	}
	return nil
}

// ValidateOriginalTarget validates and lightly normalizes the display-only
// value the user typed (an IP literal or a domain). It never drives execution:
// the Agent only ever receives a normalized numeric target IP.
func ValidateOriginalTarget(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", NewError(ErrInvalidRequest, "target is required")
	}
	if len(s) > MaxOriginalTargetLen {
		return "", NewError(ErrInvalidRequest, "target is too long")
	}
	if !utf8.ValidString(s) {
		return "", NewError(ErrInvalidRequest, "target is not valid UTF-8")
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", NewError(ErrInvalidRequest, "target contains control characters")
		}
	}
	return s, nil
}

// SanitizeText strips invalid UTF-8, control characters (including ANSI
// escape sequences) and Unicode format characters from untrusted metadata,
// trims whitespace and caps the result at maxRunes runes. It is used for
// every externally supplied string that may be stored or rendered.
func SanitizeText(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		i += size
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
		n++
		if n >= maxRunes {
			break
		}
	}
	return strings.TrimSpace(b.String())
}
