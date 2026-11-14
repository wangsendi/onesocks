package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"onesocks/internal/api"
	"onesocks/internal/config"
	"onesocks/internal/engine"
	"onesocks/internal/engine/singbox"
	"onesocks/internal/service"
	"onesocks/internal/socks"
	"onesocks/internal/webui"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("onesocks stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to YAML config (empty uses local defaults)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("onesocks %s (sing-box v1.14.4)\n", version)
		return nil
	}
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments; use -help for usage")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	// Manager owns its lifecycle. Signal cancellation only initiates orderly
	// shutdown; it must not invalidate an engine while an API update is committing.
	manager, err := service.New(context.Background(), service.Options{
		DataDir: cfg.DataDir, OutboundInterface: cfg.OutboundInterface,
		FetchTimeout: 30 * time.Second, RefreshInterval: 6 * time.Hour,
		DrainTimeout: 5 * time.Minute,
		Factory: func(ctx context.Context, nodes []engine.Node) (engine.Engine, error) {
			return singbox.NewWithOptions(ctx, nodes, singbox.Options{OutboundInterface: cfg.OutboundInterface})
		},
		Version: version,
	})
	if err != nil {
		return fmt.Errorf("initialize service: %w", err)
	}
	defer manager.Close()
	socksListener, err := net.Listen("tcp", cfg.SOCKSListen)
	if err != nil {
		return fmt.Errorf("listen SOCKS5: %w", err)
	}
	defer socksListener.Close()
	apiListener, err := net.Listen("tcp", cfg.APIListen)
	if err != nil {
		return fmt.Errorf("listen API: %w", err)
	}
	defer apiListener.Close()

	// Updates serialize and may queue behind other fetches. Streaming batches
	// use per-probe and per-write deadlines instead of this total request limit.
	const requestTimeout = 3 * time.Minute
	cfg.SOCKSListen = socksListener.Addr().String()
	cfg.APIListen = apiListener.Addr().String()
	apiHandler := webui.New(api.New(manager, cfg))
	httpServer := &http.Server{
		Handler:           withRequestTimeout(apiHandler, requestTimeout),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      requestTimeout + 5*time.Second,
		IdleTimeout:       time.Minute,
	}
	socksServer := socks.New(manager, socks.Config{Password: cfg.SOCKSPassword})
	socksCtx, cancelSocks := context.WithCancel(context.Background())
	defer cancelSocks()
	apiDone, socksDone := make(chan error, 1), make(chan error, 1)
	go func() { apiDone <- httpServer.Serve(apiListener) }()
	go func() { socksDone <- socksServer.Serve(socksCtx, socksListener) }()
	manager.Start()
	slog.Info("onesocks started", "socks", socksListener.Addr(), "api", apiListener.Addr(), "outbound_interface", cfg.OutboundInterface, "version", version)

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	var serveErr error
	apiExited, socksExited := false, false
	select {
	case <-signalCtx.Done():
		slog.Info("shutting down")
	case err := <-apiDone:
		apiExited = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			serveErr = fmt.Errorf("serve API: %w", err)
		}
	case err := <-socksDone:
		socksExited = true
		if err != nil {
			serveErr = fmt.Errorf("serve SOCKS5: %w", err)
		}
	}
	// Stop SOCKS sessions first so all generation leases are returned before
	// manager.Close waits for engine retirement.
	cancelSocks()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Minute)
	shutdownErr := httpServer.Shutdown(shutdownCtx)
	cancelShutdown()
	if shutdownErr != nil {
		_ = httpServer.Close()
	}
	if !socksExited {
		if err := <-socksDone; serveErr == nil && err != nil {
			serveErr = fmt.Errorf("stop SOCKS5: %w", err)
		}
	}
	if !apiExited {
		<-apiDone
	}
	if serveErr != nil {
		return serveErr
	}
	if shutdownErr != nil {
		return fmt.Errorf("HTTP shutdown: %w", shutdownErr)
	}
	return nil
}

func withRequestTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/nodes/probe" {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
