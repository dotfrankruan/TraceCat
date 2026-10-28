package model

// Probe is one normalized probe reply (or lack of reply) for a single TTL.
// All fields except Success are optional because NextTrace may not be able to
// obtain GeoIP, PTR or ASN data for every hop.
type Probe struct {
	Success bool `json:"success"`
	// Address is the canonical numeric IP that answered, when Success is true.
	Address string `json:"address,omitempty"`
	// PTR is the reverse DNS hostname reported by NextTrace, if any.
	PTR string `json:"ptr,omitempty"`
	// RTTMS is the round-trip time in milliseconds, nil when unavailable.
	RTTMS *float64 `json:"rtt_ms,omitempty"`
	// ErrorCode is "" for successful probes. For failed probes it is one of
	// "no_reply", "unreachable" or "unknown". "no_reply" must not be presented
	// as proof that the route is broken: intermediate routers commonly do not
	// answer probes.
	ErrorCode string `json:"error_code,omitempty"`
	// ASN is the autonomous system number, nil when unknown.
	ASN *uint32 `json:"asn,omitempty"`
	// ASName is the AS organization name, sanitized plain text.
	ASName  string   `json:"as_name,omitempty"`
	Country string   `json:"country,omitempty"`
	Region  string   `json:"region,omitempty"`
	City    string   `json:"city,omitempty"`
	Owner   string   `json:"owner,omitempty"`
	ISP     string   `json:"isp,omitempty"`
	Prefix  string   `json:"prefix,omitempty"`
	Lat     *float64 `json:"lat,omitempty"`
	Lng     *float64 `json:"lng,omitempty"`
	MPLS    []string `json:"mpls,omitempty"`
}

// Hop groups all probes observed for one TTL.
type Hop struct {
	TTL    int     `json:"ttl"`
	Probes []Probe `json:"probes"`
}

// TraceSummary is derived, never invented, from observed hops.
type TraceSummary struct {
	HopCount int `json:"hop_count"`
	// ReachedDestination is true only when a successful probe's address equals
	// the requested target IP. An intermediate timeout never sets this false
	// as a conclusion about the route; it only means the destination was not
	// observed.
	ReachedDestination bool `json:"reached_destination"`
	// DestinationRTTMS is the minimum RTT observed to the destination, nil when
	// the destination was not observed.
	DestinationRTTMS *float64 `json:"destination_rtt_ms,omitempty"`
	// Replies is the number of successful probes across all hops.
	Replies int `json:"replies"`
	// Probes is the total number of probes reported by NextTrace.
	Probes int `json:"probes"`
}

// Summarize computes a TraceSummary from normalized hops. It never fabricates
// metadata: missing data stays missing. targetIP must be a canonical numeric
// IP string; comparison is textual against already-normalized probe addresses.
func Summarize(hops []Hop, targetIP string) TraceSummary {
	sum := TraceSummary{HopCount: len(hops)}
	var best *float64
	for _, h := range hops {
		for _, p := range h.Probes {
			sum.Probes++
			if !p.Success {
				continue
			}
			sum.Replies++
			if p.Address == targetIP {
				sum.ReachedDestination = true
				if p.RTTMS != nil && (best == nil || *p.RTTMS < *best) {
					v := *p.RTTMS
					best = &v
				}
			}
		}
	}
	sum.DestinationRTTMS = best
	return sum
}

// NodeResult is the per-Agent portion of a distributed job. It is stored by
// the Controller and returned by the Controller API.
type NodeResult struct {
	NodeID   string     `json:"node_id"`
	NodeName string     `json:"node_name"`
	Location string     `json:"location,omitempty"`
	Provider string     `json:"provider,omitempty"`
	Status   NodeStatus `json:"status"`
	// Interface is the source network interface selected for this node (empty
	// means automatic routing).
	Interface string `json:"interface,omitempty"`
	// StartedAt and EndedAt are RFC3339Nano UTC timestamps; nil when the node
	// has not entered that phase.
	StartedAt        string        `json:"started_at,omitempty"`
	EndedAt          string        `json:"ended_at,omitempty"`
	DurationMS       *int64        `json:"duration_ms,omitempty"`
	NextTraceVersion string        `json:"nexttrace_version,omitempty"`
	ParserSchema     string        `json:"parser_schema,omitempty"`
	Summary          *TraceSummary `json:"summary,omitempty"`
	Hops             []Hop         `json:"hops,omitempty"`
	Error            *APIError     `json:"error,omitempty"`
}
