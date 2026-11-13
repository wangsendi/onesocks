package webui

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
)

func TestEmbeddedResources(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("public UI request reached the protected API")
		w.WriteHeader(http.StatusUnauthorized)
	})
	handler := New(api)
	for _, asset := range []struct{ path, file string }{
		{"/", "assets/index.html"},
		{"/assets/app.css", "assets/app.css"},
		{"/assets/app.js", "assets/app.js"},
	} {
		t.Run(asset.path, func(t *testing.T) {
			body, err := assets.ReadFile(asset.file)
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, asset.path, nil))
			if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) == "" || recorder.Body.String() != string(body) {
				t.Fatalf("embedded resource: status=%d, body length=%d", recorder.Code, recorder.Body.Len())
			}
			if recorder.Header().Get("Content-Type") != mime.TypeByExtension(path.Ext(asset.file)) || recorder.Header().Get("X-Content-Type-Options") != "nosniff" || recorder.Header().Get("Cache-Control") != "no-cache" {
				t.Fatalf("static resource headers: %v", recorder.Header())
			}
			head := httptest.NewRecorder()
			handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, asset.path, nil))
			if head.Code != http.StatusOK || head.Body.Len() != 0 {
				t.Fatalf("HEAD status=%d, body=%q", head.Code, head.Body.String())
			}
		})
	}
}

func TestAPIRequestsPassThroughUnchanged(t *testing.T) {
	type contextKey struct{}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions, "CUSTOM"} {
		for _, path := range []string{"/api", "/api/nodes?subscription_id=one%2Ftwo", "/api//raw/../path?value=a%23b"} {
			for _, token := range []string{"", "wrong", "admin-secret"} {
				t.Run(method+" "+path+" "+token, func(t *testing.T) {
					request := httptest.NewRequest(method, path, strings.NewReader("original body"))
					request = request.WithContext(context.WithValue(request.Context(), contextKey{}, "kept"))
					if token != "" {
						request.Header.Set("Authorization", "Bearer "+token)
					}
					called := false
					api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						called = true
						if r != request || r.Context().Value(contextKey{}) != "kept" || r.Method != method || r.RequestURI != path {
							t.Fatal("API request was replaced, normalized, or lost its context")
						}
						w.Header().Set("X-API-Response", "unchanged")
						if r.Header.Get("Authorization") != "Bearer admin-secret" {
							w.Header().Set("WWW-Authenticate", "Bearer")
							w.WriteHeader(http.StatusUnauthorized)
							_, _ = fmt.Fprint(w, `{"error":"unauthorized"}`)
							return
						}
						w.Header().Set("Allow", "GET")
						w.WriteHeader(http.StatusMethodNotAllowed)
						_, _ = fmt.Fprint(w, `{"error":"method_not_allowed"}`)
					})
					recorder := httptest.NewRecorder()
					New(api).ServeHTTP(recorder, request)
					wantStatus, wantBody := http.StatusUnauthorized, `{"error":"unauthorized"}`
					if token == "admin-secret" {
						wantStatus, wantBody = http.StatusMethodNotAllowed, `{"error":"method_not_allowed"}`
					}
					if !called || recorder.Code != wantStatus || recorder.Body.String() != wantBody || recorder.Header().Get("X-API-Response") != "unchanged" {
						t.Fatalf("API response changed: status=%d, body=%q, headers=%v", recorder.Code, recorder.Body.String(), recorder.Header())
					}
					if token == "admin-secret" && recorder.Header().Get("Allow") != "GET" {
						t.Fatal("API Allow header was changed")
					}
				})
			}
		}
	}
}

func TestUnknownStaticPathsDoNotFallBackToHTMLOrAPI(t *testing.T) {
	handler := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unknown static path reached API")
	}))
	for _, path := range []string{"/unknown", "/assets/unknown.js", "/assets/", "/ui/config", "/ui/config/", "/apix", "/index.html"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s: status=%d, want 404", path, recorder.Code)
		}
	}
}
