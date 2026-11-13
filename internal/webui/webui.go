// Package webui embeds the local management page and forwards API requests.
package webui

import (
	"bytes"
	"embed"
	"net/http"
	"strings"
	"time"
)

//go:embed assets/*
var assets embed.FS

func New(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, r, "assets/index.html")
	})
	mux.HandleFunc("GET /assets/{file...}", func(w http.ResponseWriter, r *http.Request) {
		serveAsset(w, r, "assets/"+r.PathValue("file"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Forward before ServeMux so its path cleaning cannot redirect or alter
		// existing API routes, methods, authentication or request context.
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func serveAsset(w http.ResponseWriter, r *http.Request, name string) {
	data, err := assets.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}
