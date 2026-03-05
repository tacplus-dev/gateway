package internal

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/routes"
)

// NewGateway creates a grpc-gateway ServeMux and registers all downstream
// service handlers, each pointing to the health resolver for load-balanced routing.
func NewGateway(ctx context.Context, gwRoutes []routes.Route) (*runtime.ServeMux, error) {
	mux := runtime.NewServeMux()
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`),
	}

	for _, route := range gwRoutes {
		target := fmt.Sprintf("%s:///%s", resolverScheme, route.ServiceID)
		if err := route.RegisterFunc(ctx, mux, target, dialOpts); err != nil {
			return nil, fmt.Errorf("register gateway handler for %s: %w", route.ServiceID, err)
		}
		zap.L().Info("Registered REST gateway route",
			zap.String("service", route.ServiceID),
			zap.String("target", target))
	}

	return mux, nil
}
