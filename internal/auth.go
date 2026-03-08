package internal

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	wrapperJwk "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/libs/jwk"
	tokenlib "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/libs/token"
	"gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/routes"
	jwkviewpb "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/types/libs/jwkview"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GatewayAuth performs lightweight token pre-validation at the gateway layer.
// It verifies JWT signature and expiry but does NOT check audience or entitlements
// (that's the backend's responsibility). This rejects obviously invalid requests
// early to protect backends from unauthenticated load.
type GatewayAuth struct {
	jwks *gatewayJwkMap
}

// NewGatewayAuth creates a GatewayAuth that watches JWKs from the kernel connection.
// The conn must provide access to JwkVerifyingKeysViewService.
func NewGatewayAuth(ctx context.Context, conn grpc.ClientConnInterface) *GatewayAuth {
	jwks := &gatewayJwkMap{entries: make(map[string]*wrapperJwk.ImmutableJwk)}
	if conn != nil {
		viewClient := jwkviewpb.NewJwkVerifyingKeysViewServiceClient(conn)
		go jwks.watchView(ctx, viewClient)
	}
	zap.L().Info("Gateway token pre-validation initialized",
		zap.Bool("jwk_watch", conn != nil))
	return &GatewayAuth{jwks: jwks}
}

// ValidateToken checks whether the request on fullMethod requires authentication
// and, if so, verifies the token signature and expiry. Returns a gRPC status error
// on failure so it can be returned directly from stream handlers.
//
// For gRPC: fullMethod is "/package.Service/Method".
// For REST: fullMethod is "/api/{service}/v1/...".
func (ga *GatewayAuth) ValidateToken(ctx context.Context, fullMethod string) error {
	if ga.isNoAuth(fullMethod) {
		return nil
	}

	// Extract bearer token from metadata.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}

	authValues := md.Get("authorization")
	if len(authValues) == 0 || authValues[0] == "" {
		return status.Error(codes.Unauthenticated, "missing authorization header")
	}

	tokenStr := authValues[0]
	if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
		tokenStr = tokenStr[7:]
	}

	// Parse and verify signature + expiry.
	tw, err := tokenlib.ParseToken(tokenStr)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	kid := tw.GetKid()
	if kid == "" {
		return status.Error(codes.Unauthenticated, "token missing key ID (kid)")
	}

	jwk := ga.jwks.get(kid)
	if jwk == nil {
		return status.Errorf(codes.Unauthenticated, "unknown signing key: %s", kid)
	}

	if err := tw.Verify(jwk); err != nil {
		return status.Errorf(codes.Unauthenticated, "token verification failed: %v", err)
	}

	return nil
}

// isNoAuth checks whether the given method/path targets a no-auth service.
func (ga *GatewayAuth) isNoAuth(fullMethod string) bool {
	// gRPC: "/package.Service/Method" → extract "package"
	if strings.HasPrefix(fullMethod, "/") && !strings.HasPrefix(fullMethod, "/api/") {
		method := strings.TrimPrefix(fullMethod, "/")
		if dotIdx := strings.Index(method, "."); dotIdx > 0 {
			pkg := method[:dotIdx]
			return routes.NoAuthServices[pkg]
		}
	}

	// REST: "/api/{service}/v1/..." → extract "service"
	if strings.HasPrefix(fullMethod, "/api/") {
		parts := strings.SplitN(fullMethod, "/", 4) // ["", "api", "service", ...]
		if len(parts) >= 3 {
			return routes.NoAuthServices[parts[2]]
		}
	}

	return false
}

// AuthMiddleware wraps an http.Handler with gateway token pre-validation for REST routes.
func AuthMiddleware(next http.Handler, auth *GatewayAuth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.isNoAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Only validate /api/* routes — static assets don't need auth.
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := authHeader
		if strings.HasPrefix(strings.ToLower(tokenStr), "bearer ") {
			tokenStr = tokenStr[7:]
		}

		tw, err := tokenlib.ParseToken(tokenStr)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid token: %v"}`, err), http.StatusUnauthorized)
			return
		}

		kid := tw.GetKid()
		if kid == "" {
			http.Error(w, `{"error":"token missing key ID (kid)"}`, http.StatusUnauthorized)
			return
		}

		jwk := auth.jwks.get(kid)
		if jwk == nil {
			http.Error(w, fmt.Sprintf(`{"error":"unknown signing key: %s"}`, kid), http.StatusUnauthorized)
			return
		}

		if err := tw.Verify(jwk); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"token verification failed: %v"}`, err), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// gatewayJwkMap is a thread-safe map of kid → ImmutableJwk, populated by watching
// the JwkVerifyingKeysViewService. This is structurally identical to the jwkMap
// in frontendserver/authorizer.go but lives in the gateway package (can't import
// generated frontendserver code from the gateway binary).
type gatewayJwkMap struct {
	mu      sync.RWMutex
	entries map[string]*wrapperJwk.ImmutableJwk
}

func (m *gatewayJwkMap) get(kid string) *wrapperJwk.ImmutableJwk {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.entries[kid]
}

func (m *gatewayJwkMap) watchView(ctx context.Context, client jwkviewpb.JwkVerifyingKeysViewServiceClient) {
	for {
		stream, err := client.Watch(ctx, &emptypb.Empty{})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			zap.L().Error("Gateway: failed to watch JwkVerifyingKeysView", zap.Error(err))
			continue
		}

		for {
			resp, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				zap.L().Warn("Gateway: JwkVerifyingKeysView watch stream ended", zap.Error(err))
				break
			}

			newEntries := make(map[string]*wrapperJwk.ImmutableJwk, len(resp.Entries))
			for kid, proto := range resp.Entries {
				immutable, err := wrapperJwk.NewImmutableJwk(proto)
				if err != nil {
					zap.L().Warn("Gateway: skipping invalid JWK",
						zap.String("kid", kid),
						zap.Error(err))
					continue
				}
				newEntries[kid] = immutable
			}

			m.mu.Lock()
			m.entries = newEntries
			m.mu.Unlock()

			zap.L().Info("Gateway JWK view updated", zap.Int("count", len(newEntries)))
		}
	}
}
