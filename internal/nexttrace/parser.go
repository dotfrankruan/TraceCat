package nexttrace

import (
	"bytes"
	"encoding/json"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/dotfrankruan/tracecat/internal/model"
)

// DefaultMaxRawBytes bounds the raw JSON result retained for debugging.
const DefaultMaxRawBytes = 1 << 20

const (
	maxPTRLen       = 253
	maxNameLen      = 128
	maxPrefixLen    = 64
	maxMPLSEntries  = 8
	maxMPLSEntryLen = 64
	maxTTL          = 65_535
)

// ParseOptions configures one parse of NextTrace JSON output.
type ParseOptions struct {
	// TargetIP is the canonical numeric destination that was traced. It is
	// used only to derive reached_destination / destination_rtt_ms.
	TargetIP string
	// MaxRawBytes bounds the raw output retained in the result. Values <= 0
	// use DefaultMaxRawBytes.
	MaxRawBytes int
}

// Parsed is the normalized, model-facing result of one successful parse.
type Parsed struct {
	Hops               []model.Hop
	Summary            model.TraceSummary
	RawResult          json.RawMessage
	RawResultTruncated bool
}

// Parse converts NextTrace JSON into model hops. It supports the current
// grouped output ({"Hops":[[{...}],...]}) and the flat variant
// ({"Hops":[{...}]}). Unknown and newly added fields are ignored. Structural
// problems never produce partial results: they return parse_error.
func Parse(raw []byte, opts ParseOptions) (Parsed, *model.APIError) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return Parsed{}, parseError("nexttrace produced no output")
	}
	if !json.Valid(trimmed) {
		return Parsed{}, parseError("nexttrace output is not valid JSON")
	}

	var top struct {
		Hops json.RawMessage `json:"Hops"`
	}
	if err := json.Unmarshal(trimmed, &top); err != nil {
		return Parsed{}, parseError("nexttrace output has an unexpected structure")
	}
	hopsRaw := bytes.TrimSpace(top.Hops)
	if len(hopsRaw) == 0 || bytes.Equal(hopsRaw, []byte("null")) {
		return Parsed{}, parseError("nexttrace output contains no hop data")
	}

	hops, err := decodeHops(hopsRaw)
	if err != nil {
		return Parsed{}, parseError("nexttrace output has an unexpected structure")
	}

	result := Parsed{
		Hops:    hops,
		Summary: model.Summarize(hops, opts.TargetIP),
	}
	maxRaw := opts.MaxRawBytes
	if maxRaw <= 0 {
		maxRaw = DefaultMaxRawBytes
	}
	if len(trimmed) > maxRaw {
		result.RawResultTruncated = true
	} else {
		result.RawResult = json.RawMessage(append([]byte(nil), trimmed...))
	}
	return result, nil
}

func parseError(message string) *model.APIError {
	return model.NewError(model.ErrParseError, message)
}

func decodeHops(raw json.RawMessage) ([]model.Hop, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errUnexpectedShape
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		return nil, errUnexpectedShape
	}

	groups := make(map[int][]model.Probe)
	for i, entry := range entries {
		entry = bytes.TrimSpace(entry)
		if len(entry) == 0 || bytes.Equal(entry, []byte("null")) {
			continue
		}
		switch entry[0] {
		case '[':
			var probes []json.RawMessage
			if err := json.Unmarshal(entry, &probes); err != nil {
				return nil, errUnexpectedShape
			}
			for _, probeRaw := range probes {
				if err := appendProbe(groups, probeRaw, i+1); err != nil {
					return nil, err
				}
			}
		case '{':
			if err := appendProbe(groups, entry, i+1); err != nil {
				return nil, err
			}
		default:
			return nil, errUnexpectedShape
		}
	}

	ttls := make([]int, 0, len(groups))
	for ttl := range groups {
		ttls = append(ttls, ttl)
	}
	sort.Ints(ttls)

	hops := make([]model.Hop, 0, len(ttls))
	for _, ttl := range ttls {
		hops = append(hops, model.Hop{TTL: ttl, Probes: groups[ttl]})
	}
	return hops, nil
}

var errUnexpectedShape = &shapeError{}

type shapeError struct{}

func (*shapeError) Error() string { return "unexpected nexttrace JSON shape" }

func appendProbe(groups map[int][]model.Probe, raw json.RawMessage, fallbackTTL int) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] != '{' {
		return errUnexpectedShape
	}
	var hop rawHop
	if err := json.Unmarshal(trimmed, &hop); err != nil {
		return errUnexpectedShape
	}

	ttl, ok := looseInt(hop.TTL)
	if !ok || ttl <= 0 || ttl > maxTTL {
		ttl = int64(fallbackTTL)
	}
	probe, err := hop.normalize()
	if err != nil {
		return err
	}
	groups[int(ttl)] = append(groups[int(ttl)], probe)
	return nil
}

// rawHop mirrors one NextTrace hop entry. All fields are kept as raw JSON so
// type drift in the external tool never crashes the Agent; known fields are
// interpreted strictly enough to be useful, unknown fields are ignored.
type rawHop struct {
	TTL     json.RawMessage `json:"TTL"`
	Success json.RawMessage `json:"Success"`
	Address json.RawMessage `json:"Address"`
	Domain  json.RawMessage `json:"Domain"`
	RTT     json.RawMessage `json:"Rtt"`
	Error   json.RawMessage `json:"Error"`
	Geo     json.RawMessage `json:"Geo"`
	MPLS    json.RawMessage `json:"MPLS"`
}

func (h rawHop) normalize() (model.Probe, error) {
	var probe model.Probe

	success, hasSuccess := looseBool(h.Success)
	ip, addressDomain := parseAddress(h.Address)
	domain := addressDomain
	if domain == "" {
		domain = looseString(h.Domain)
	}

	if !hasSuccess && ip != "" {
		// Be tolerant of partial output where Success is omitted but an
		// address is present. This does not invent data, it infers the single
		// unambiguous meaning of an answered probe.
		success = true
	}

	if success {
		probe.Success = true
		probe.Address = ip
		probe.PTR = model.SanitizeText(domain, maxPTRLen)
		probe.RTTMS = rttMilliseconds(h.RTT)
		geo := parseGeo(h.Geo)
		applyGeo(&probe, geo)
		probe.MPLS = parseMPLS(h.MPLS)
		return probe, nil
	}

	probe.Success = false
	text := errorText(h.Error)
	switch {
	case text == "":
		probe.ErrorCode = "no_reply"
	case strings.Contains(strings.ToLower(text), "unreachable"):
		probe.ErrorCode = "unreachable"
	default:
		probe.ErrorCode = "unknown"
	}
	return probe, nil
}

func applyGeo(probe *model.Probe, geo geoInfo) {
	country := sanitizeName(pickNonEmpty(geo.CountryEn, geo.Country))
	region := sanitizeName(pickNonEmpty(geo.ProvEn, geo.Prov))
	city := sanitizeName(pickNonEmpty(geo.CityEn, geo.City))

	probe.ASN = parseASN(geo.ASNumber)
	probe.ASName = sanitizeName(geo.Organization)
	probe.Owner = sanitizeName(geo.Owner)
	probe.ISP = sanitizeName(geo.ISP)
	probe.Country = country
	probe.Region = region
	probe.City = city
	probe.Prefix = model.SanitizeText(geo.Prefix, maxPrefixLen)
	if probe.PTR == "" {
		probe.PTR = model.SanitizeText(geo.PTR, maxPTRLen)
	}

	geoIdentity := model.SanitizeText(geo.IP, maxNameLen) != "" || country != ""
	hasCoordinates := geo.HasLat && geo.HasLng &&
		!math.IsNaN(geo.Lat) && !math.IsNaN(geo.Lng) &&
		!math.IsInf(geo.Lat, 0) && !math.IsInf(geo.Lng, 0) &&
		geo.Lat >= -90 && geo.Lat <= 90 && geo.Lng >= -180 && geo.Lng <= 180
	if hasCoordinates && (geoIdentity || geo.Lat != 0 || geo.Lng != 0) {
		lat, lng := geo.Lat, geo.Lng
		probe.Lat = &lat
		probe.Lng = &lng
	}
}

func sanitizeName(s string) string {
	return model.SanitizeText(s, maxNameLen)
}

func pickNonEmpty(preferred, fallback string) string {
	if strings.TrimSpace(preferred) != "" {
		return preferred
	}
	return fallback
}

// geoInfo is the tolerant, internal representation of NextTrace's Geo object.
// The wire model is derived from it only after sanitization and validation.
type geoInfo struct {
	IP           string
	Country      string
	CountryEn    string
	Prov         string
	ProvEn       string
	City         string
	CityEn       string
	ASNumber     string
	Organization string
	Owner        string
	ISP          string
	Prefix       string
	PTR          string
	Lat          float64
	Lng          float64
	HasLat       bool
	HasLng       bool
}

func parseGeo(raw json.RawMessage) geoInfo {
	var geo geoInfo
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return geo
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return geo
	}
	for key, value := range fields {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "ip":
			geo.IP = looseString(value)
		case "country":
			geo.Country = looseString(value)
		case "country_en", "countryen":
			geo.CountryEn = looseString(value)
		case "prov", "province", "region":
			geo.Prov = looseString(value)
		case "prov_en", "proven", "province_en", "region_en":
			geo.ProvEn = looseString(value)
		case "city":
			geo.City = looseString(value)
		case "city_en", "cityen":
			geo.CityEn = looseString(value)
		case "asnumber", "as_number", "asn":
			geo.ASNumber = looseScalar(value)
		case "organization", "organisation", "org", "as_name", "asname":
			geo.Organization = looseString(value)
		case "owner":
			geo.Owner = looseString(value)
		case "isp":
			geo.ISP = looseString(value)
		case "prefix", "cidr":
			geo.Prefix = looseString(value)
		case "ptr", "hostname", "reverse", "domain":
			if geo.PTR == "" {
				geo.PTR = looseString(value)
			}
		case "lat", "latitude":
			if v, ok := looseFloat(value); ok {
				geo.Lat, geo.HasLat = v, true
			}
		case "lng", "lon", "long", "longitude":
			if v, ok := looseFloat(value); ok {
				geo.Lng, geo.HasLng = v, true
			}
		}
	}
	return geo
}

func parseASN(s string) *uint32 {
	s = strings.TrimSpace(s)
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "AS") {
		s = strings.TrimSpace(s[2:])
	}
	if s == "" {
		return nil
	}
	var value uint64
	if parsed, err := strconv.ParseUint(s, 10, 64); err == nil {
		value = parsed
	} else if parsed, err := strconv.ParseFloat(s, 64); err == nil && parsed > 0 && parsed <= math.MaxUint32 {
		value = uint64(parsed)
	} else {
		return nil
	}
	if value == 0 || value > math.MaxUint32 {
		return nil
	}
	asn := uint32(value)
	return &asn
}

func rttMilliseconds(raw json.RawMessage) *float64 {
	f, ok := looseFloat(raw)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return nil
	}
	// NextTrace reports RTT in nanoseconds. Convert to milliseconds and keep
	// three decimal places.
	ms := math.Round((f/1e6)*1000) / 1000
	return &ms
}

func parseAddress(raw json.RawMessage) (ip, domain string) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", ""
	}
	switch trimmed[0] {
	case '"':
		value := looseString(trimmed)
		if canonical, ok := canonicalIP(value); ok {
			return canonical, ""
		}
		return "", value
	case '{':
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &fields); err != nil {
			return "", ""
		}
		for key, value := range fields {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "ip":
				ip = looseString(value)
			case "domain", "hostname", "ptr":
				if domain == "" {
					domain = looseString(value)
				}
			}
		}
		if canonical, ok := canonicalIP(ip); ok {
			ip = canonical
		} else {
			if domain == "" {
				domain = ip
			}
			ip = ""
		}
		return ip, domain
	default:
		return "", ""
	}
}

// canonicalIP parses a numeric IP and returns its canonical (unmapped,
// zone-free) string form. Hostnames, bracketed forms and zone identifiers are
// not valid NextTrace hop addresses and are omitted.
func canonicalIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	return addr.Unmap().String(), true
}

func errorText(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	switch trimmed[0] {
	case '"':
		return looseString(trimmed)
	case '{':
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &fields); err != nil {
			return ""
		}
		for _, wanted := range []string{"message", "error", "msg", "reason", "detail"} {
			for key, value := range fields {
				if strings.ToLower(strings.TrimSpace(key)) == wanted {
					if text := looseString(value); text != "" {
						return text
					}
				}
			}
		}
		return ""
	default:
		return looseScalar(trimmed)
	}
}

func parseMPLS(raw json.RawMessage) []string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] != '[' {
		if entry := mplsEntry(trimmed); entry != "" {
			return []string{entry}
		}
		return nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if len(out) >= maxMPLSEntries {
			break
		}
		if value := mplsEntry(entry); value != "" {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mplsEntry(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	if trimmed[0] == '"' {
		return model.SanitizeText(looseString(trimmed), maxMPLSEntryLen)
	}
	if trimmed[0] == '{' {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &fields); err == nil {
			var label, ttl string
			for key, value := range fields {
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "label":
					label = looseScalar(value)
				case "ttl":
					ttl = looseScalar(value)
				}
			}
			parts := make([]string, 0, 2)
			if label != "" {
				parts = append(parts, "label="+label)
			}
			if ttl != "" {
				parts = append(parts, "ttl="+ttl)
			}
			if len(parts) > 0 {
				return model.SanitizeText(strings.Join(parts, " "), maxMPLSEntryLen)
			}
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, trimmed); err != nil {
		return ""
	}
	return model.SanitizeText(compact.String(), maxMPLSEntryLen)
}

// loose helpers intentionally tolerate type drift in the external tool. A
// field with an unexpected JSON type is treated as absent rather than failing
// the whole trace.

func looseString(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	if trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return ""
		}
		return value
	}
	return looseScalar(trimmed)
}

func looseScalar(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	if trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return ""
		}
		return value
	}
	return string(trimmed)
}

func looseInt(raw json.RawMessage) (int64, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return 0, false
	}
	value := looseScalar(trimmed)
	if value == "" {
		return 0, false
	}
	if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
		return parsed, true
	}
	if parsed, err := strconv.ParseFloat(value, 64); err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
		return int64(parsed), true
	}
	return 0, false
}

func looseBool(raw json.RawMessage) (bool, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false, false
	}
	value := strings.ToLower(strings.TrimSpace(looseScalar(trimmed)))
	switch value {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	default:
		return false, false
	}
}

func looseFloat(raw json.RawMessage) (float64, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return 0, false
	}
	value := strings.TrimSpace(looseScalar(trimmed))
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}
