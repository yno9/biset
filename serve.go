package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/vault"
	jmapserver "github.com/yno9/go-jmapserver"
)


func startJMAPServer(ctx context.Context, cfg *vault.Config, store *jmapserver.Store, mgr *Manager) func() {
	srv := cfg.Server
	port := srv.Port
	bind := srv.Bind
	accountID := filepath.Base(cfg.Vault)

	jmapHub := jmapserver.NewHub()
	notify := func() { jmapHub.Notify() }

	vaultNameMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Vault-Name", accountID)
			next.ServeHTTP(w, r)
		})
	}

	uiPath := resolveUI(cfg.Server.Interface, cfg.Vault)

	handler := &jmapHandler{accountID: jmap.ID(accountID), store: store, mgr: mgr}
	jmapCfg := jmapserver.Config{
		ListenAddr: fmt.Sprintf("%s:%d", bind, port),
		Password:   srv.Password,
		AuthFunc: func(user, pw string) (jmap.ID, bool) {
			if user == srv.RelayName && pw == srv.Password {
				return jmap.ID(accountID), true
			}
			return "", false
		},
	}
	mux := jmapserver.NewMux(jmapCfg, handler, jmapHub)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || uiPath == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, uiPath)
	})

	addr := fmt.Sprintf("%s:%d", bind, port)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: vaultNameMiddleware(mux),
	}
	go func() {
		<-ctx.Done()
		httpServer.Shutdown(context.Background()) //nolint:errcheck
	}()
	go func() {
		log.Printf("[jmap] listening on %s  vault=%s", addr, cfg.Vault)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[jmap] stopped: %v", err)
		}
	}()
	return notify
}

// ── helpers ───────────────────────────────────────────────────────────────────

func resolveUI(interfacePath, vaultDir string) string {
	if exe, err := os.Executable(); err == nil {
		if c := filepath.Join(filepath.Dir(exe), "index.html"); fileExists(c) {
			return c
		}
	}
	if c := filepath.Join(filepath.Dir(vaultDir), "index.html"); fileExists(c) {
		return c
	}
	if interfacePath != "" {
		if c, err := expandHome(interfacePath); err == nil && fileExists(c) {
			return c
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[2:]), nil
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

