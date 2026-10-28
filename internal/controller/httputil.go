package controller

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; " +
	"form-action 'self'; object-src 'none'"

const permissionsPolicy = "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()"

// statusForErrorCode maps stable API error codes to HTTP status codes.
func statusForErrorCode(code model.ErrorCode) int {
	switch code {
	case model.ErrInvalidRequest:
		return http.StatusBadRequest
	case model.ErrUnauthorized:
		return http.StatusUnauthorized
	case model.ErrForbidden, model.ErrCSRFFailed:
		return http.StatusForbidden
	case model.ErrNotFound, model.ErrNoAddresses:
		return http.StatusNotFound
	case model.ErrConflict:
		return http.StatusConflict
	case model.ErrPayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case model.ErrTargetRejected:
		return http.StatusUnprocessableEntity
	case model.ErrRateLimited:
		return http.StatusTooManyRequests
	case model.ErrBusy:
		return http.StatusServiceUnavailable
	case model.ErrDNSError:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// writeJSON serializes v and writes it with the JSON content type. Marshal
// errors are converted to a generic internal error without leaking details.
func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, model.NewError(model.ErrInternal, "internal error"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func writeAPIError(w http.ResponseWriter, status int, apiErr *model.APIError) {
	if apiErr == nil {
		apiErr = model.NewError(model.ErrInternal, "internal error")
	}
	if status == http.StatusTooManyRequests {
		// Rate limits are short fixed windows; a conservative hint is enough for
		// well-behaved clients and matches the Agent's behaviour.
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, status, model.ErrorResponse{Error: apiErr})
}

func writeError(w http.ResponseWriter, code model.ErrorCode, message string) {
	writeAPIError(w, statusForErrorCode(code), model.NewError(code, message))
}

// decodeJSONBody strictly decodes a size-limited JSON body (unknown fields and
// trailing data are rejected).
func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) *model.APIError {
	if r.Body == nil {
		return model.NewError(model.ErrInvalidRequest, "request body is required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return model.NewError(model.ErrPayloadTooLarge, "request body is too large")
		}
		return model.NewError(model.ErrInvalidRequest, "invalid JSON body")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return model.NewError(model.ErrPayloadTooLarge, "request body is too large")
		}
		return model.NewError(model.ErrInvalidRequest, "invalid JSON body")
	}
	return nil
}

// allowedMethods enforces an exact method allowlist and returns a JSON 405 with
// an Allow header otherwise.
func allowedMethods(handler http.HandlerFunc, methods ...string) http.HandlerFunc {
	allow := strings.Join(methods, ", ")
	return func(w http.ResponseWriter, r *http.Request) {
		for _, method := range methods {
			if r.Method == method {
				handler(w, r)
				return
			}
		}
		w.Header().Set("Allow", allow)
		writeAPIError(w, http.StatusMethodNotAllowed, model.NewError(model.ErrInvalidRequest, "method not allowed"))
	}
}

// clientIP returns the TCP peer address unless the peer is a configured trusted
// proxy, in which case the nearest non-trusted forwarding hop is used. Spoofed
// forwarding headers from untrusted peers are ignored.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	peer, peerOK := parseRemoteAddr(r.RemoteAddr)
	peerString := r.RemoteAddr
	if peerOK {
		peerString = peer.String()
		if !isTrustedProxy(peer, trusted) {
			return peerString
		}
	}
	if !peerOK {
		return peerString
	}
	xForwardedFor := r.Header.Values("X-Forwarded-For")
	for _, value := range xForwardedFor {
		parts := strings.Split(value, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if candidate == "" {
				continue
			}
			addr, err := netip.ParseAddr(candidate)
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			if !isTrustedProxy(addr, trusted) {
				return addr.String()
			}
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if addr, err := netip.ParseAddr(realIP); err == nil {
			return addr.Unmap().String()
		}
	}
	return peerString
}

func parseRemoteAddr(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func isTrustedProxy(addr netip.Addr, trusted []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// statusWriter records the response status for logging and exposes Flush for
// SSE responses.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	bytes       int
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// securityHeaders applies the Controller's static security headers. It never
// enables CORS.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", permissionsPolicy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// recoverPanics converts panics into a generic JSON 500 without exposing stack
// traces or internal state to clients. The panic is logged server-side.
func recoverPanics(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered", "method", r.Method, "path", r.URL.Path, "panic", rec)
				if !sw.wroteHeader {
					writeAPIError(sw, http.StatusInternalServerError, model.NewError(model.ErrInternal, "internal error"))
				}
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

// requestLogger logs one line per request without headers, cookies or query
// strings (which could carry sensitive data).
func requestLogger(logger *slog.Logger, trusted []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"bytes", sw.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"client", clientIP(r, trusted),
		)
	})
}
