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
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	gw "gitlab.com/secondstarcavalier/controlplane/services/gateway/internal"
	"gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/libs/logger"
	"gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/libs/serviceconfig"
	sm "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/sm"
	x509wrapper "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/libs/x509"
	serviceconfig_pb "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/types/libs/serviceconfig"
	gateway_pb "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/types/services/gateway"
	"gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/routes"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

//go:embed dist
var webFS embed.FS

//go:embed tacplus/registry.json tacplus/registry.schema.json tacplus/AGENT.md
var registryFS embed.FS

func main() {
	if err := run(); err != nil {
		log.Fatalf("gateway: %v", err)
	}
}

func run() error {
	// 1. Load serviceconfig via generated loaders (-c/--config flag or BOOTSTRAP_CONFIG env var).
	cfg, _ := serviceconfig.LoadLocalConfig()
	if cfg == nil {
		cfg = &serviceconfig_pb.Config{}
	}
	serviceconfig_pb.ConfigDefaults(cfg)

	configData, _ := readConfigFile()
	gatewayCfg := &gateway_pb.Config{}
	if configData != nil {
		var err error
		gatewayCfg, err = gateway_pb.ConfigFromBytes(configData)
		if err != nil {
			return fmt.Errorf("gateway config: %w", err)
		}
	}
	gateway_pb.ConfigDefaults(gatewayCfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// 2. Install logger.
	if cfg.Logger != nil {
		if _, err := logger.InstallFromConfig(cfg.Logger); err != nil {
			return fmt.Errorf("logger: %w", err)
		}
	}

	// 3. Connect to kernel via ServiceManager.
	svcMgr, err := sm.New()
	if err != nil {
		return fmt.Errorf("servicemanager: %w", err)
	}
	defer svcMgr.Close()

	// 4. Start HealthWatcher (watches ServiceHealthState.instances).
	healthBackend := svcMgr.BackendClients().Services().ServiceHealthState()
	hw, err := gw.NewHealthWatcher(ctx, healthBackend.BackendStub())
	if err != nil {
		return fmt.Errorf("health watcher: %w", err)
	}
	_ = hw // retained for future use (health UI endpoint)

	// 5. Create gateway token pre-validator (signature + expiry only).
	// Uses the same JWK view watch stream as backend frontendserver authorizers.
	gatewayAuth := gw.NewGatewayAuth(ctx, svcMgr.Conn())

	// 6. Create grpc-gateway mux for REST→gRPC transcoding (from generated routes).
	gwMux, err := gw.NewGateway(ctx, routes.GatewayRoutes)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}

	// 7. Create gRPC server with typed passthrough handlers for all frontend services.
	// Each handler: Authorize (entitlement check) → forward via typed frontend client.
	grpcServer := grpc.NewServer()
	svcMgr.RegisterPassthrough(grpcServer)

	// 10. Build combined HTTP handler: /api/* → gateway, everything else → SPA.
	var webContent fs.FS
	if webRoot := os.Getenv("WEB_ROOT"); webRoot != "" {
		webContent = os.DirFS(webRoot)
		zap.L().Info("Serving webapp from filesystem", zap.String("path", webRoot))
	} else {
		webContent, err = fs.Sub(webFS, "dist")
		if err != nil {
			return fmt.Errorf("embed fs: %w", err)
		}
		zap.L().Info("Serving webapp from embedded filesystem")
	}
	httpHandler := gw.AuthMiddleware(buildHandler(gwMux, webContent), gatewayAuth)

	// 11. Load TLS from service_config.
	certPair, err := x509wrapper.NewImmutableX509CertPair(cfg.GetTlsCert())
	if err != nil {
		return fmt.Errorf("tls cert: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*certPair.TlsCert()},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	// 12. Resolve listen addresses.
	host := ""
	if la := cfg.GetListenAddress(); la != nil {
		host = la.Host
	}
	tcpAddr := fmt.Sprintf("%s:%d", host, gatewayCfg.GetTcpPort())
	udpAddr := fmt.Sprintf("%s:%d", host, gatewayCfg.GetUdpPort())

	enableHTTP := gatewayCfg.GetEnableHttp()
	enableHTTP3 := gatewayCfg.GetEnableHttp3()
	enableGRPC := gatewayCfg.GetEnableGrpc()
	if !enableHTTP && !enableHTTP3 && !enableGRPC {
		return fmt.Errorf("at least one of enable_http, enable_http3, or enable_grpc must be true")
	}

	zap.L().Info("Starting gateway",
		zap.String("tcp_addr", tcpAddr),
		zap.String("udp_addr", udpAddr),
		zap.Bool("http", enableHTTP),
		zap.Bool("http3", enableHTTP3),
		zap.Bool("grpc", enableGRPC))

	// 13. HTTP/3 (QUIC) server for REST and SPA — UDP port.
	var h3Server *http3.Server
	if enableHTTP3 {
		h3Server = &http3.Server{
			Addr:      udpAddr,
			TLSConfig: tlsConfig,
			Handler:   httpHandler,
		}
	}

	// 14. HTTP/1.1, HTTP/2, and gRPC server — TCP port.
	// Multiplexes gRPC and HTTP by content type based on enabled protocols.
	// When HTTP/3 is enabled, sets Alt-Svc header to advertise it.
	needsTCP := enableHTTP || enableGRPC
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if enableGRPC && r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
				grpcServer.ServeHTTP(w, r)
			} else if enableHTTP {
				if h3Server != nil {
					if err := h3Server.SetQUICHeaders(w.Header()); err != nil {
						zap.L().Debug("Failed to set Alt-Svc header", zap.Error(err))
					}
				}
				httpHandler.ServeHTTP(w, r)
			} else {
				http.Error(w, "HTTP not enabled", http.StatusServiceUnavailable)
			}
		}),
	}

	g, gCtx := errgroup.WithContext(ctx)

	if needsTCP {
		lis, err := tls.Listen("tcp", tcpAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tcp listen %s: %w", tcpAddr, err)
		}
		defer lis.Close()

		g.Go(func() error {
			zap.L().Info("Serving TLS (TCP)", zap.String("addr", tcpAddr))
			if err := httpServer.Serve(lis); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("serve tcp: %w", err)
			}
			return nil
		})
	}

	if enableHTTP3 {
		udpConn, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("udp listen %s: %w", udpAddr, err)
		}
		defer udpConn.Close()

		g.Go(func() error {
			zap.L().Info("Serving HTTP/3 (QUIC/UDP)", zap.String("addr", udpAddr))
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
		if cfg.GetShutdownTimeoutSeconds() > 0 {
			shutdownTimeout = time.Duration(cfg.GetShutdownTimeoutSeconds()) * time.Second
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if enableGRPC {
			grpcServer.GracefulStop()
		}
		if h3Server != nil {
			if err := h3Server.Close(); err != nil {
				zap.L().Warn("HTTP/3 server close error", zap.Error(err))
			}
		}
		if needsTCP {
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				zap.L().Warn("HTTP server shutdown error", zap.Error(err))
			}
		}

		zap.L().Info("Graceful shutdown complete")
		return nil
	})

	return g.Wait()
}

// readConfigFile reads the config file from -c/--config flag or BOOTSTRAP_CONFIG env var.
func readConfigFile() ([]byte, error) {
	path := ""
	for i := 1; i < len(os.Args)-1; i++ {
		if os.Args[i] == "-c" || os.Args[i] == "--config" {
			path = os.Args[i+1]
			break
		}
	}
	if path == "" {
		path = os.Getenv("BOOTSTRAP_CONFIG")
	}
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}

// buildHandler returns an HTTP handler that routes:
//   - /api/* → grpc-gateway mux (REST API)
//   - /registry/* → embedded registry files (always from embed, independent of WEB_ROOT)
//   - everything else → SPA (with fallback to index.html for client-side routing)
func buildHandler(gwMux http.Handler, webContent fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(webContent))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			gwMux.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/registry/") {
			serveRegistryFile(w, r)
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

// serveRegistryFile serves embedded registry files independently of WEB_ROOT.
// Files are always served from the compiled-in registryFS embed.
func serveRegistryFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/registry/")

	allowed := map[string]string{
		"registry.json":        "application/json",
		"registry.schema.json": "application/json",
		"AGENT.md":             "text/markdown; charset=utf-8",
	}

	contentType, ok := allowed[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	data, err := fs.ReadFile(registryFS, "tacplus/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(data)
}

