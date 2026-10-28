// Package webui serves the compiled React dashboard that is embedded into the
// Controller binary. The build pipeline (Makefile / Vite) writes the assets to
// internal/webui/public. When the dashboard has not been built, a small
// plain-text placeholder is served instead of failing or exposing a directory
// listing.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:public
var embedded embed.FS

const placeholder = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>TraceCat</title></head>
<body style="background:#0b0f14;color:#e6edf3;font-family:monospace;padding:2rem">
<h1>TraceCat UI is not built</h1>
<p>Build the dashboard and the Controller with:</p>
<pre>make build</pre>
<p>Or build only the dashboard with:</p>
<pre>pnpm --dir web install &amp;&amp; pnpm --dir web build</pre>
</body></html>
`

// FS returns the embedded dashboard filesystem (rooted at the public dir).
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "public")
	if err != nil {
		// The embedded tree always contains "public"; this is unreachable.
		panic("webui: embedded public directory missing")
	}
	return sub
}

// Handler serves the single-page dashboard with an index.html fallback for
// client-side routes. Hashed build assets are cached immutably; HTML is never
// cached. It never renders directory listings.
func Handler() http.Handler {
	files := FS()
	server := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		name := strings.TrimPrefix(clean, "/")
		if name != "" {
			if info, err := fs.Stat(files, name); err == nil && !info.IsDir() {
				if strings.HasPrefix(clean, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				server.ServeHTTP(w, r)
				return
			}
		}
		// Serve index.html for "/" and for extension-less client routes.
		if clean == "/" || path.Ext(clean) == "" {
			index, err := fs.ReadFile(files, "index.html")
			if err != nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(placeholder))
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = w.Write(index)
			}
			return
		}
		http.NotFound(w, r)
	})
}
