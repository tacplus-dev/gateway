package main

import (
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	gw "gitlab.com/secondstarcavalier/controlplane/services/springsteen/internal"
	"gitlab.com/secondstarcavalier/controlplane/services/springsteen/tacplus/libs/logger"
	"gitlab.com/secondstarcavalier/controlplane/services/springsteen/tacplus/libs/servicemanager"
	x509wrapper "gitlab.com/secondstarcavalier/controlplane/services/springsteen/tacplus/libs/x509"
	serviceconfig_pb "gitlab.com/secondstarcavalier/controlplane/services/springsteen/tacplus/types/libs/serviceconfig"
	springsteen_pb "gitlab.com/secondstarcavalier/controlplane/services/springsteen/tacplus/types/services/springsteen"
	"gitlab.com/secondstarcavalier/controlplane/services/springsteen/tacplus/routes"
	"gitlab.com/secondstarcavalier/controlplane/services/springsteen/tacplus/wrappers/backends"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

//go:embed webapp
var webFS embed.FS

func main() {
	if err := run(); err != nil {
		log.Fatalf("springsteen: %v", err)
	}
}

func run() error {
	// 1. Load serviceconfig (both Config and BootstrapConfig from the same YAML).
	configPath := resolveConfigPath()
	if configPath == "" {
		return fmt.Errorf("no config: use --config flag or set SERVICE_CONFIG env var")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config %s: %w", configPath, err)
	}

	cfg, err := serviceconfig_pb.ConfigFromBytes(data)
	if err != nil {
		return fmt.Errorf("parsing config %s: %w", configPath, err)
	}

	bsCfg, err := serviceconfig_pb.BootstrapConfigFromBytes(data)
	if err != nil {
		return fmt.Errorf("parsing bootstrap config %s: %w", configPath, err)
	}

	springsteenCfg, err := springsteen_pb.ConfigFromBytes(data)
	if err != nil {
		return fmt.Errorf("parsing springsteen config %s: %w", configPath, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// 2. Install logger.
	if cfg.Logger != nil {
		if _, err := logger.InstallFromConfig(cfg.Logger); err != nil {
			return fmt.Errorf("logger: %w", err)
		}
	}

	// 3. Connect to elvis via ServiceManager.
	sc, err := servicemanager.NewServiceManager(ctx, bsCfg)
	if err != nil {
		return fmt.Errorf("servicemanager: %w", err)
	}
	defer sc.Close()

	// 4. Create backend clients.
	bc, err := backends.NewBackends(ctx, sc)
	if err != nil {
		return fmt.Errorf("backends: %w", err)
	}
	defer bc.Close()

	// 5. Start HealthWatcher (watches ServiceHealthState.instances).
	healthBackend := bc.Services().ServiceHealthState()
	hw, err := gw.NewHealthWatcher(ctx, healthBackend.BackendStub())
	if err != nil {
		return fmt.Errorf("health watcher: %w", err)
	}

	// 6. Create health-aware gRPC resolver.
	resolver := gw.NewHealthResolver(hw)

	// 7. Create grpc-gateway mux for REST→gRPC transcoding (from generated routes).
	gwMux, err := gw.NewGateway(ctx, routes.GatewayRoutes)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}

	// 8. Create gRPC server with transparent proxy for unknown services.
	grpcServer := grpc.NewServer(
		grpc.UnknownServiceHandler(gw.TransparentHandler(resolver)),
	)

	// 9. Build combined HTTP handler: /api/* → gateway, everything else → SPA.
	var webContent fs.FS
	if webRoot := os.Getenv("WEB_ROOT"); webRoot != "" {
		// If WEB_ROOT/dist doesn't exist, extract embedded webapp to bootstrap it
		if _, err := os.Stat(filepath.Join(webRoot, "dist")); os.IsNotExist(err) {
			zap.L().Info("Extracting embedded webapp to WEB_ROOT", zap.String("path", webRoot))
			if err := extractEmbeddedWebapp(webFS, webRoot); err != nil {
				return fmt.Errorf("extracting webapp to %s: %w", webRoot, err)
			}
		}
		webContent = os.DirFS(filepath.Join(webRoot, "dist"))
		zap.L().Info("Serving webapp from filesystem", zap.String("path", filepath.Join(webRoot, "dist")))
	} else {
		webContent, err = fs.Sub(webFS, "webapp/dist")
		if err != nil {
			return fmt.Errorf("embed fs: %w", err)
		}
		zap.L().Info("Serving webapp from embedded filesystem")
	}
	httpHandler := buildHandler(gwMux, webContent)

	// 10. Load TLS from service_config.
	certPair, err := x509wrapper.NewImmutableX509CertPair(cfg.GetTlsCert())
	if err != nil {
		return fmt.Errorf("tls cert: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*certPair.TlsCert()},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	// 11. Resolve listen address.
	listenAddr := cfg.GetListenAddress()
	if listenAddr == "" {
		listenAddr = ":8443"
	}

	enableTCP := springsteenCfg.GetEnableTcp()
	enableQUIC := springsteenCfg.GetEnableQuic()
	if !enableTCP && !enableQUIC {
		return fmt.Errorf("at least one of enable_tcp or enable_quic must be true")
	}

	zap.L().Info("Starting springsteen",
		zap.String("addr", listenAddr),
		zap.Bool("tcp", enableTCP),
		zap.Bool("quic", enableQUIC))

	// 12. HTTP/3 (QUIC) server for REST and SPA — same port, UDP.
	var h3Server *http3.Server
	if enableQUIC {
		h3Server = &http3.Server{
			Addr:      listenAddr,
			TLSConfig: tlsConfig,
			Handler:   httpHandler,
		}
	}

	// 13. HTTP/1.1 and HTTP/2 server — multiplexes gRPC and HTTP by content type.
	// When QUIC is enabled, sets Alt-Svc header to advertise HTTP/3.
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
				grpcServer.ServeHTTP(w, r)
			} else {
				if h3Server != nil {
					if err := h3Server.SetQUICHeaders(w.Header()); err != nil {
						zap.L().Debug("Failed to set Alt-Svc header", zap.Error(err))
					}
				}
				httpHandler.ServeHTTP(w, r)
			}
		}),
	}

	g, gCtx := errgroup.WithContext(ctx)

	if enableTCP {
		lis, err := tls.Listen("tcp", listenAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tcp listen %s: %w", listenAddr, err)
		}
		defer lis.Close()

		g.Go(func() error {
			zap.L().Info("Serving TLS (TCP)", zap.String("addr", listenAddr))
			if err := httpServer.Serve(lis); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("serve tcp: %w", err)
			}
			return nil
		})
	}

	if enableQUIC {
		udpConn, err := net.ListenPacket("udp", listenAddr)
		if err != nil {
			return fmt.Errorf("udp listen %s: %w", listenAddr, err)
		}
		defer udpConn.Close()

		g.Go(func() error {
			zap.L().Info("Serving HTTP/3 (QUIC/UDP)", zap.String("addr", listenAddr))
			if err := h3Server.Serve(udpConn); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("serve quic: %w", err)
			}
			return nil
		})
	}

	// Graceful shutdown.
	g.Go(func() error {
		<-gCtx.Done()
		zap.L().Info("Shutdown signal received")

		shutdownTimeout := 30 * time.Second
		if cfg.ShutdownTimeoutSeconds > 0 {
			shutdownTimeout = time.Duration(cfg.ShutdownTimeoutSeconds) * time.Second
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		grpcServer.GracefulStop()
		if h3Server != nil {
			if err := h3Server.Close(); err != nil {
				zap.L().Warn("HTTP/3 server close error", zap.Error(err))
			}
		}
		if enableTCP {
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				zap.L().Warn("HTTP server shutdown error", zap.Error(err))
			}
		}

		zap.L().Info("Graceful shutdown complete")
		return nil
	})

	return g.Wait()
}

// resolveConfigPath finds the config file path from -c/--config flag or SERVICE_CONFIG env var.
func resolveConfigPath() string {
	for i := 1; i < len(os.Args)-1; i++ {
		if os.Args[i] == "-c" || os.Args[i] == "--config" {
			return os.Args[i+1]
		}
	}
	return os.Getenv("SERVICE_CONFIG")
}

// extractEmbeddedWebapp walks the embedded webapp FS and writes all files to targetDir.
// The embedded FS has paths like "webapp/src/App.tsx" — we strip the "webapp/" prefix.
func extractEmbeddedWebapp(embeddedFS embed.FS, targetDir string) error {
	return fs.WalkDir(embeddedFS, "webapp", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath := strings.TrimPrefix(path, "webapp/")
		if relPath == "" || path == "webapp" {
			return nil
		}
		targetPath := filepath.Join(targetDir, relPath)

		if d.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}

		data, err := embeddedFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading embedded %s: %w", path, err)
		}
		return os.WriteFile(targetPath, data, 0644)
	})
}

// buildHandler returns an HTTP handler that routes:
//   - /api/* → grpc-gateway mux (REST API)
//   - everything else → embedded SPA (with fallback to index.html for client-side routing)
func buildHandler(gwMux http.Handler, webContent fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(webContent))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			gwMux.ServeHTTP(w, r)
			return
		}

		// Try to serve static file. If not found, serve index.html (SPA routing).
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(webContent, path); err != nil {
			// File not found — serve index.html for SPA client-side routing.
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

