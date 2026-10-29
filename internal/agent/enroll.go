package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	defaultEnrollRefreshSeconds = 300
	minEnrollRefreshSeconds     = 60
	maxEnrollRefreshSeconds     = 3600
	minEnrollmentSecretLength   = 32
	enrollmentTimeout           = 10 * time.Second
	enrollmentBodyLimit         = 64 << 10
	maxEndpointURLLength        = 512
)

// AdvertiseURL returns the URL the Controller should use to reach this Agent.
// It defaults to "http://"+listen and is only meaningful in controller mode.
func (c *Config) AdvertiseURL() string {
	if c.Controller == nil {
		return ""
	}
	if c.Controller.AdvertiseURL != "" {
		return c.Controller.AdvertiseURL
	}
	return "http://" + c.Listen
}

// validateController validates the optional controller enrollment section.
func (c *Config) validateController() error {
	controller := c.Controller
	if controller == nil {
		return nil
	}
	if controller.RefreshSeconds < minEnrollRefreshSeconds || controller.RefreshSeconds > maxEnrollRefreshSeconds {
		return fmt.Errorf("controller.refresh_seconds must be between %d and %d",
			minEnrollRefreshSeconds, maxEnrollRefreshSeconds)
	}
	if !envNamePattern.MatchString(controller.EnrollmentTokenEnv) {
		return errors.New("controller.enrollment_token_env must be a valid environment variable name")
	}
	secret, ok := os.LookupEnv(controller.EnrollmentTokenEnv)
	if !ok {
		return fmt.Errorf("controller.enrollment_token_env %q is not set", controller.EnrollmentTokenEnv)
	}
	if len(secret) < minEnrollmentSecretLength {
		return fmt.Errorf("controller.enrollment_token_env %q must contain at least %d characters",
			controller.EnrollmentTokenEnv, minEnrollmentSecretLength)
	}

	controllerURL, err := validateEndpointURL(controller.URL, "controller.url")
	if err != nil {
		return err
	}
	advertiseURL, err := validateEndpointURL(c.AdvertiseURL(), "controller.advertise_url")
	if err != nil {
		return err
	}

	for field, value := range map[string]string{
		"controller.name":     controller.Name,
		"controller.location": controller.Location,
		"controller.provider": controller.Provider,
	} {
		if value == "" {
			continue
		}
		if model.SanitizeText(value, model.MaxLabelRunes) != value {
			return fmt.Errorf("%s contains control characters or is too long", field)
		}
	}

	listenAddr, _, err := parseListen(c.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	controllerLoopback := endpointHostIsLoopback(controllerURL)
	advertiseLoopback := endpointHostIsLoopback(advertiseURL)
	if listenAddr.IsLoopback() && !controllerLoopback && controller.AdvertiseURL == "" {
		return errors.New("controller.advertise_url is required when the listen address is loopback and the controller is not local")
	}
	if advertiseLoopback && !controllerLoopback {
		return errors.New("controller.advertise_url must not point at a loopback address when the controller is remote")
	}
	return nil
}

// validateEndpointURL enforces the Controller/Agent transport rules: https for
// any valid host, but http only for a literal non-public IP address. URLs must
// not carry userinfo, a query, a fragment or a path.
func validateEndpointURL(raw, field string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	if raw != strings.TrimSpace(raw) || len(raw) > maxEndpointURLLength {
		return nil, fmt.Errorf("%s is invalid", field)
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" {
		return nil, fmt.Errorf("%s is not a valid absolute URL", field)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%s must use http or https", field)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%s must not contain userinfo", field)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must not contain a query or fragment", field)
	}
	if parsed.Path != "" {
		return nil, fmt.Errorf("%s must not contain a path", field)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%s must include a host", field)
	}
	if parsed.Scheme == "http" {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("%s may use http only with a literal non-public IP address", field)
		}
		if addr.Zone() != "" {
			return nil, fmt.Errorf("%s must not contain a zone identifier", field)
		}
		if !ipguard.IsNonPublic(addr.Unmap()) {
			return nil, fmt.Errorf("%s must use https for a public address", field)
		}
		return parsed, nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return nil, fmt.Errorf("%s must not contain a zone identifier", field)
		}
	} else if !validDNSHostname(host) {
		return nil, fmt.Errorf("%s has an invalid host", field)
	}
	return parsed, nil
}

func validDNSHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-' && i != 0 && i != len(label)-1:
			default:
				return false
			}
		}
	}
	return true
}

func endpointHostIsLoopback(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// enrollmentClient talks to the Controller enrollment endpoint. The enrollment
// secret and the returned trace token are kept in memory only and never
// logged.
type enrollmentClient struct {
	endpoint        string
	enrollmentToken string
	advertiseURL    string
	name            string
	location        string
	provider        string
	nextTrace       string
	protocols       []string
	httpClient      *http.Client
}

func newEnrollmentClient(cfg Config, nextTraceVersion string, protocols []string) (*enrollmentClient, error) {
	if cfg.Controller == nil {
		return nil, errors.New("controller enrollment is not configured")
	}
	secret, ok := os.LookupEnv(cfg.Controller.EnrollmentTokenEnv)
	if !ok {
		return nil, fmt.Errorf("controller.enrollment_token_env %q is not set", cfg.Controller.EnrollmentTokenEnv)
	}
	if len(secret) < minEnrollmentSecretLength {
		return nil, fmt.Errorf("controller.enrollment_token_env %q must contain at least %d characters",
			cfg.Controller.EnrollmentTokenEnv, minEnrollmentSecretLength)
	}
	name := cfg.Controller.Name
	if name == "" {
		name = cfg.Name
	}
	transport := &http.Transport{
		Proxy:                 nil, // never route the enrollment secret through an environment proxy
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &enrollmentClient{
		endpoint:        cfg.Controller.URL + model.EnrollmentPath,
		enrollmentToken: secret,
		advertiseURL:    cfg.AdvertiseURL(),
		name:            name,
		location:        cfg.Controller.Location,
		provider:        cfg.Controller.Provider,
		nextTrace:       nextTraceVersion,
		protocols:       append([]string{}, protocols...),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   enrollmentTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// enrollOnce performs one enrollment/refresh call and atomically installs the
// returned token so subsequent inbound Controller requests authenticate.
func (a *Agent) enrollOnce(ctx context.Context) error {
	if a.enrollment == nil {
		return errors.New("controller enrollment is not configured")
	}
	token, err := a.enrollment.enroll(ctx, a.cfg.NodeID)
	if err != nil {
		return err
	}
	a.auth.setToken(token)
	a.logger.Info("agent enrolled with controller",
		"controller", a.cfg.Controller.URL,
		"advertise_url", a.enrollment.advertiseURL)
	return nil
}

// runEnrollment retries enrollment with bounded exponential backoff until it
// succeeds, then refreshes periodically. Failures are logged safely and the
// Agent continues serving (401 until a token is available).
func (a *Agent) runEnrollment(ctx context.Context) {
	if a.enrollment == nil {
		return
	}
	minBackoff := a.enrollRetryMin
	if minBackoff <= 0 {
		minBackoff = time.Second
	}
	maxBackoff := a.enrollRetryMax
	if maxBackoff < minBackoff {
		maxBackoff = 30 * time.Second
	}
	refresh := a.enrollRefresh
	if refresh <= 0 {
		refresh = time.Duration(defaultEnrollRefreshSeconds) * time.Second
	}

	backoff := minBackoff
	for {
		err := a.enrollOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.logger.Warn("agent enrollment attempt failed; retrying",
				"error", err.Error(), "retry_in", backoff.String())
			if !sleepContext(ctx, backoff) {
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = minBackoff
		if !sleepContext(ctx, refresh) {
			return
		}
	}
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// enroll performs the actual HTTP enrollment for nodeID. Error messages are
// safe: they never contain the enrollment secret, the returned token or the raw
// response body.
func (c *enrollmentClient) enroll(ctx context.Context, nodeID string) (string, error) {
	requestBody := model.AgentEnrollRequest{
		SchemaVersion:    model.AgentSchemaVersion,
		NodeID:           nodeID,
		Name:             c.name,
		Location:         c.location,
		Provider:         c.provider,
		URL:              c.advertiseURL,
		NextTraceVersion: c.nextTrace,
		Protocols:        append([]string{}, c.protocols...),
	}
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return "", errors.New("could not encode the enrollment request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", errors.New("could not build the enrollment request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.enrollmentToken)

	response, err := c.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("controller enrollment request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Drain a little so the connection can be reused; never expose the body.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("controller enrollment returned HTTP status %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, enrollmentBodyLimit+1))
	if err != nil {
		return "", errors.New("could not read the controller enrollment response")
	}
	if int64(len(body)) > enrollmentBodyLimit {
		return "", errors.New("controller enrollment response is too large")
	}
	var enrollResponse model.AgentEnrollResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&enrollResponse); err != nil {
		return "", errors.New("controller enrollment response is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", errors.New("controller enrollment response has trailing data")
	}

	if enrollResponse.SchemaVersion != model.ControllerSchemaVersion {
		return "", errors.New("controller enrollment response has an unsupported schema_version")
	}
	if enrollResponse.NodeID != nodeID {
		return "", errors.New("controller enrollment response node_id does not match")
	}
	if !validInboundToken(enrollResponse.AgentToken) {
		return "", errors.New("controller enrollment response has an invalid agent_token")
	}
	if !sameEndpointURL(enrollResponse.TraceURL, c.advertiseURL) {
		return "", errors.New("controller enrollment response trace_url does not match the advertised URL")
	}
	return enrollResponse.AgentToken, nil
}

// sameEndpointURL compares two absolute endpoint URLs after normalizing scheme
// and host casing, IP form and explicit ports. The Controller normalizes the
// advertised URL before echoing it as trace_url, so byte equality would reject
// otherwise valid enrollments.
func sameEndpointURL(left, right string) bool {
	normalizedLeft, ok := normalizeEndpointURL(left)
	if !ok {
		return false
	}
	normalizedRight, ok := normalizeEndpointURL(right)
	if !ok {
		return false
	}
	return normalizedLeft == normalizedRight
}

func normalizeEndpointURL(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
	}
	if port := parsed.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, true
}

// validInboundToken accepts a non-empty, bounded, visible-ASCII bearer token.
func validInboundToken(token string) bool {
	if token == "" || len(token) > 4096 {
		return false
	}
	for _, r := range token {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
