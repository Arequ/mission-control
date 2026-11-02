package httpapi

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed openapi.yaml
var openAPISpec []byte

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(openAPISpec)
}

func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/repo/") {
		http.NotFound(w, r)
		return
	}
	if s.webDir == "" {
		http.NotFound(w, r)
		return
	}
	root, err := filepath.Abs(s.webDir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rel := strings.TrimPrefix(filepath.Clean("/"+r.URL.Path), "/")
	if rel == "" || rel == "." {
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
		return
	}
	full := filepath.Join(root, rel)
	abs, err := filepath.Abs(full)
	if err != nil || (abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator))) {
		http.NotFound(w, r)
		return
	}
	if st, err := os.Stat(abs); err == nil && !st.IsDir() {
		http.ServeFile(w, r, abs)
		return
	}
	index := filepath.Join(root, "index.html")
	if _, err := os.Stat(index); err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, index)
}
