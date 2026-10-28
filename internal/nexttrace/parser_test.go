package nexttrace

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const groupedFixture = `{
  "Hops": [
    [
      {"TTL":1,"Success":true,"Address":{"IP":"10.200.0.1","Domain":"gw1.example.net"},"Rtt":2682000,
       "Geo":{"ip":"10.200.0.1","country":"中国","country_en":"China","prov":"东京","prov_en":"Tokyo","city":"东京","city_en":"Tokyo","asnumber":"AS64512","organization":"Example Net","isp":"Example ISP","prefix":"10.200.0.0/16","lat":35.68,"lng":139.76}},
      {"TTL":1,"Success":false,"Address":{"IP":""},"Rtt":0,"Error":null},
      {"TTL":1,"Success":false,"Error":{}}
    ],
    [
      {"TTL":2,"Success":true,"Address":{"IP":"1.1.1.1","Domain":"one.one.one.one"},"Rtt":41217000,
       "Geo":{"country":"澳大利亚","country_en":"Australia","asnumber":"13335","organization":"Cloudflare, Inc.","isp":"Cloudflare","prefix":"1.1.1.0/24","lat":-33.49,"lng":151.0},
       "MPLS":[{"label":123,"ttl":1}],"FutureField":{"anything":true}}
    ]
  ],
  "TraceMapUrl":"https://example.invalid/trace?id=1",
  "UnknownTopLevel":123
}`

func TestParseGroupedOutput(t *testing.T) {
	t.Parallel()
	parsed, apiErr := Parse([]byte(groupedFixture), ParseOptions{TargetIP: "1.1.1.1"})
	if apiErr != nil {
		t.Fatalf("Parse: %v", apiErr)
	}
	if len(parsed.Hops) != 2 {
		t.Fatalf("hop count = %d, want 2", len(parsed.Hops))
	}
	if parsed.Hops[0].TTL != 1 || parsed.Hops[1].TTL != 2 {
		t.Fatalf("TTLs = %d,%d; want ascending 1,2", parsed.Hops[0].TTL, parsed.Hops[1].TTL)
	}
	if len(parsed.Hops[0].Probes) != 3 {
		t.Fatalf("ttl 1 probe count = %d, want 3", len(parsed.Hops[0].Probes))
	}

	first := parsed.Hops[0].Probes[0]
	if !first.Success {
		t.Fatal("first probe should be successful")
	}
	if first.Address != "10.200.0.1" {
		t.Fatalf("address = %q, want 10.200.0.1", first.Address)
	}
	if first.PTR != "gw1.example.net" {
		t.Fatalf("ptr = %q, want gw1.example.net", first.PTR)
	}
	if first.RTTMS == nil || *first.RTTMS != 2.682 {
		t.Fatalf("rtt = %v, want 2.682", first.RTTMS)
	}
	if first.ASN == nil || *first.ASN != 64512 {
		t.Fatalf("asn = %v, want 64512", first.ASN)
	}
	if first.Country != "China" || first.Region != "Tokyo" || first.City != "Tokyo" {
		t.Fatalf("geo = %q/%q/%q, want English values", first.Country, first.Region, first.City)
	}
	if first.ISP != "Example ISP" || first.Prefix != "10.200.0.0/16" {
		t.Fatalf("isp/prefix = %q/%q", first.ISP, first.Prefix)
	}
	if first.Lat == nil || first.Lng == nil || *first.Lat != 35.68 || *first.Lng != 139.76 {
		t.Fatalf("lat/lng = %v/%v, want 35.68/139.76", first.Lat, first.Lng)
	}

	if got := parsed.Hops[0].Probes[1].ErrorCode; got != "no_reply" {
		t.Fatalf("null Error error_code = %q, want no_reply", got)
	}
	if got := parsed.Hops[0].Probes[2].ErrorCode; got != "no_reply" {
		t.Fatalf("empty object Error error_code = %q, want no_reply", got)
	}
	if parsed.Hops[0].Probes[1].RTTMS != nil {
		t.Fatal("failed probe must not report an RTT")
	}

	second := parsed.Hops[1].Probes[0]
	if second.Address != "1.1.1.1" || second.PTR != "one.one.one.one" {
		t.Fatalf("second address/ptr = %q/%q", second.Address, second.PTR)
	}
	if second.RTTMS == nil || *second.RTTMS != 41.217 {
		t.Fatalf("second rtt = %v, want 41.217", second.RTTMS)
	}
	if len(second.MPLS) != 1 || !strings.Contains(second.MPLS[0], "123") {
		t.Fatalf("mpls = %v, want object rendered with label", second.MPLS)
	}

	if parsed.Summary.HopCount != 2 || parsed.Summary.Probes != 4 || parsed.Summary.Replies != 2 {
		t.Fatalf("summary = %+v", parsed.Summary)
	}
	if !parsed.Summary.ReachedDestination {
		t.Fatal("destination should be reached")
	}
	if parsed.Summary.DestinationRTTMS == nil || *parsed.Summary.DestinationRTTMS != 41.217 {
		t.Fatalf("destination rtt = %v", parsed.Summary.DestinationRTTMS)
	}
	if parsed.RawResultTruncated {
		t.Fatal("raw result should be retained")
	}
	if !json.Valid(parsed.RawResult) {
		t.Fatalf("raw result is not valid JSON: %q", parsed.RawResult)
	}
	if !strings.Contains(string(parsed.RawResult), "TraceMapUrl") {
		t.Fatal("raw result should be the unmodified NextTrace JSON")
	}
}

func TestParseFlatOutput(t *testing.T) {
	t.Parallel()
	fixture := `{"Hops":[
	  {"TTL":2,"Success":false,"Error":{"message":"Destination Host Unreachable"}},
	  {"TTL":1,"Success":true,"Address":"1.1.1.1","Rtt":1000000,"Geo":null}
	]}`
	parsed, apiErr := Parse([]byte(fixture), ParseOptions{TargetIP: "1.1.1.1"})
	if apiErr != nil {
		t.Fatalf("Parse: %v", apiErr)
	}
	if len(parsed.Hops) != 2 {
		t.Fatalf("hop count = %d, want 2", len(parsed.Hops))
	}
	if parsed.Hops[0].TTL != 1 || parsed.Hops[1].TTL != 2 {
		t.Fatalf("TLTs not sorted: %d,%d", parsed.Hops[0].TTL, parsed.Hops[1].TTL)
	}
	if parsed.Hops[0].Probes[0].Address != "1.1.1.1" {
		t.Fatalf("string address not normalized: %+v", parsed.Hops[0].Probes[0])
	}
	if parsed.Hops[1].Probes[0].ErrorCode != "unreachable" {
		t.Fatalf("error code = %q, want unreachable", parsed.Hops[1].Probes[0].ErrorCode)
	}
	if parsed.Hops[1].Probes[0].Address != "" {
		t.Fatal("failed probe must not carry an address")
	}
}

func TestParseErrorCodesAndGeoNull(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hop  string
		want string
	}{
		{"null error", `{"TTL":1,"Success":false,"Error":null}`, "no_reply"},
		{"empty error object", `{"TTL":1,"Success":false,"Error":{}}`, "no_reply"},
		{"missing error", `{"TTL":1,"Success":false}`, "no_reply"},
		{"unreachable text", `{"TTL":1,"Success":false,"Error":{"message":"Destination Net Unreachable"}}`, "unreachable"},
		{"unreachable string", `{"TTL":1,"Success":false,"Error":"host unreachable"}`, "unreachable"},
		{"other text", `{"TTL":1,"Success":false,"Error":{"message":"permission denied"}}`, "unknown"},
		{"geo null", `{"TTL":1,"Success":true,"Address":{"IP":"1.1.1.1"},"Rtt":1,"Geo":null}`, ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := `{"Hops":[[` + tc.hop + `]]}`
			parsed, apiErr := Parse([]byte(fixture), ParseOptions{TargetIP: "1.1.1.1"})
			if apiErr != nil {
				t.Fatalf("Parse: %v", apiErr)
			}
			probe := parsed.Hops[0].Probes[0]
			if tc.want == "" {
				if probe.Country != "" || probe.ASN != nil || probe.Lat != nil || probe.Lng != nil {
					t.Fatalf("geo null produced synthesized metadata: %+v", probe)
				}
				return
			}
			if probe.ErrorCode != tc.want {
				t.Fatalf("error_code = %q, want %q", probe.ErrorCode, tc.want)
			}
		})
	}
}

func TestParseRTTConversion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rtt  string
		want *float64
	}{
		{"nanoseconds", `2682000`, ptrFloat(2.682)},
		{"zero means unknown", `0`, nil},
		{"negative ignored", `-5`, nil},
		{"string nanoseconds", `"41217000"`, ptrFloat(41.217)},
		{"fractional rounding", `1234567`, ptrFloat(1.235)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := `{"Hops":[[{"TTL":1,"Success":true,"Address":{"IP":"1.1.1.1"},"Rtt":` + tc.rtt + `}]]}`
			parsed, apiErr := Parse([]byte(fixture), ParseOptions{TargetIP: "1.1.1.1"})
			if apiErr != nil {
				t.Fatalf("Parse: %v", apiErr)
			}
			got := parsed.Hops[0].Probes[0].RTTMS
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("rtt = %v, want nil", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("rtt = nil, want %v", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("rtt = %v, want %v", *got, *tc.want)
			}
		})
	}
}

func ptrFloat(v float64) *float64 { return &v }

func TestParsePartialOutputIsTolerated(t *testing.T) {
	t.Parallel()
	fixture := `{"Hops":[[
	  {"Address":{"IP":"1.1.1.1"},"Rtt":"2500000"},
	  null
	], null]}`
	parsed, apiErr := Parse([]byte(fixture), ParseOptions{TargetIP: "1.1.1.1"})
	if apiErr != nil {
		t.Fatalf("Parse: %v", apiErr)
	}
	if len(parsed.Hops) != 1 || parsed.Hops[0].TTL != 1 {
		t.Fatalf("hops = %+v, want a single fallback TTL 1", parsed.Hops)
	}
	probe := parsed.Hops[0].Probes[0]
	if !probe.Success || probe.Address != "1.1.1.1" {
		t.Fatalf("partial probe not normalized: %+v", probe)
	}
	if probe.RTTMS == nil || *probe.RTTMS != 2.5 {
		t.Fatalf("rtt = %v, want 2.5", probe.RTTMS)
	}
}

func TestParseRejectsMalformedOutput(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"empty":            "",
		"not json":         "NextTrace starting...",
		"truncated":        `{"Hops":[[{"TTL":1`,
		"top-level array":  `[]`,
		"missing hops":     `{"TraceMapUrl":"https://example.invalid"}`,
		"hops not array":   `{"Hops":"nope"}`,
		"probe not object": `{"Hops":[[42]]}`,
		"null hops":        `{"Hops":null}`,
	}
	for name, fixture := range cases {
		fixture := fixture
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, apiErr := Parse([]byte(fixture), ParseOptions{TargetIP: "1.1.1.1"})
			if apiErr == nil {
				t.Fatal("Parse = nil error, want parse_error")
			}
			if apiErr.Code != model.ErrParseError {
				t.Fatalf("error code = %s, want parse_error", apiErr.Code)
			}
			if strings.Contains(apiErr.Message, "Hops") && strings.Contains(apiErr.Message, "NextTrace") {
				t.Fatalf("error message should be generic, got %q", apiErr.Message)
			}
		})
	}
}

func TestParseRawResultTruncation(t *testing.T) {
	t.Parallel()
	parsed, apiErr := Parse([]byte(groupedFixture), ParseOptions{TargetIP: "1.1.1.1", MaxRawBytes: 16})
	if apiErr != nil {
		t.Fatalf("Parse: %v", apiErr)
	}
	if !parsed.RawResultTruncated {
		t.Fatal("raw result should be marked truncated")
	}
	if len(parsed.RawResult) != 0 {
		t.Fatalf("truncated raw result should be omitted, got %d bytes", len(parsed.RawResult))
	}
	if len(parsed.Hops) != 2 {
		t.Fatal("normalized hops must still be present when raw is truncated")
	}
}

func TestParseSanitizesUntrustedStrings(t *testing.T) {
	t.Parallel()
	fixture := `{"Hops":[[{"TTL":1,"Success":true,
	  "Address":{"IP":"1.1.1.1","Domain":"\u001b[31mevil.example\u001b[0m"},
	  "Rtt":1000000,
	  "Geo":{"asnumber":"13335","organization":"\u001b[32mEvil\u0007 Corp","isp":"\u001b[31mISP\u001b[0m","prefix":"` + strings.Repeat("9", 200) + `"}}]]}`
	parsed, apiErr := Parse([]byte(fixture), ParseOptions{TargetIP: "1.1.1.1"})
	if apiErr != nil {
		t.Fatalf("Parse: %v", apiErr)
	}
	probe := parsed.Hops[0].Probes[0]
	for name, value := range map[string]string{
		"ptr":    probe.PTR,
		"asname": probe.ASName,
		"isp":    probe.ISP,
		"prefix": probe.Prefix,
	} {
		if idx := strings.IndexFunc(value, unicode.IsControl); idx >= 0 {
			t.Fatalf("%s contains control characters: %q", name, value)
		}
	}
	if len([]rune(probe.PTR)) > maxPTRLen {
		t.Fatalf("ptr longer than %d runes", maxPTRLen)
	}
	if len([]rune(probe.Prefix)) > maxPrefixLen {
		t.Fatalf("prefix longer than %d runes", maxPrefixLen)
	}
	if strings.ContainsRune(probe.ASName, '\u0007') {
		t.Fatal("ASName control character was not stripped")
	}
}

func TestParseMPLSIsBounded(t *testing.T) {
	t.Parallel()
	entries := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		entries = append(entries, `"`+strings.Repeat("m", 100)+`"`)
	}
	fixture := `{"Hops":[[{"TTL":1,"Success":true,"Address":{"IP":"1.1.1.1"},"Rtt":1,"MPLS":[` + strings.Join(entries, ",") + `]}]]}`
	parsed, apiErr := Parse([]byte(fixture), ParseOptions{TargetIP: "1.1.1.1"})
	if apiErr != nil {
		t.Fatalf("Parse: %v", apiErr)
	}
	mpls := parsed.Hops[0].Probes[0].MPLS
	if len(mpls) != maxMPLSEntries {
		t.Fatalf("mpls entries = %d, want %d", len(mpls), maxMPLSEntries)
	}
	for _, entry := range mpls {
		if len([]rune(entry)) > maxMPLSEntryLen {
			t.Fatalf("mpls entry longer than %d runes", maxMPLSEntryLen)
		}
	}
}

func TestParseGeoCoordinatesRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		geo      string
		wantLat  bool
		wantZero bool
	}{
		{"unknown zero without identity", `{"lat":0,"lng":0}`, false, false},
		{"identity allows zero zero", `{"ip":"8.8.8.8","country_en":"United States","lat":0,"lng":0}`, true, true},
		{"non-zero without identity", `{"lat":12.5,"lng":-7.25}`, true, false},
		{"out of range rejected", `{"ip":"8.8.8.8","lat":200,"lng":10}`, false, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := `{"Hops":[[{"TTL":1,"Success":true,"Address":{"IP":"8.8.8.8"},"Rtt":1,"Geo":` + tc.geo + `}]]}`
			parsed, apiErr := Parse([]byte(fixture), ParseOptions{TargetIP: "8.8.8.8"})
			if apiErr != nil {
				t.Fatalf("Parse: %v", apiErr)
			}
			probe := parsed.Hops[0].Probes[0]
			if tc.wantLat != (probe.Lat != nil && probe.Lng != nil) {
				t.Fatalf("lat/lng presence = %v/%v, want present=%v", probe.Lat, probe.Lng, tc.wantLat)
			}
			if tc.wantZero && (probe.Lat == nil || *probe.Lat != 0 || probe.Lng == nil || *probe.Lng != 0) {
				t.Fatalf("lat/lng = %v/%v, want 0/0", probe.Lat, probe.Lng)
			}
		})
	}
}
