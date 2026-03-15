package internal

import (
	"fmt"
	"io"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/routes"
)

// TransparentHandler returns a grpc.StreamHandler that forwards all unknown
// gRPC calls to downstream services via the health resolver. It extracts the
// service_id from the method name and uses the health resolver to find healthy
// backend endpoints.
//
// Token pre-validation: if auth is non-nil, requests to authenticated services
// must carry a valid JWT (signature + expiry checked). No-auth services
// (e.g., identity) are passed through without inspection.
func TransparentHandler(hr *HealthResolver, auth *GatewayAuth) grpc.StreamHandler {
	return func(srv interface{}, serverStream grpc.ServerStream) error {
		fullMethod, ok := grpc.MethodFromServerStream(serverStream)
		if !ok {
			return status.Error(codes.Internal, "failed to get method from stream")
		}

		// Pre-validate token before forwarding to backend.
		if auth != nil {
			if err := auth.ValidateToken(serverStream.Context(), fullMethod); err != nil {
				return err
			}
		}

		serviceID, err := resolveServiceID(fullMethod)
		if err != nil {
			return status.Errorf(codes.Unimplemented, "unknown service: %s", fullMethod)
		}

		target := fmt.Sprintf("%s:///%s", ResolverScheme, serviceID)
		conn, err := grpc.NewClient(target,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`),
		)
		if err != nil {
			return status.Errorf(codes.Unavailable, "connect to %s: %v", serviceID, err)
		}
		defer conn.Close()

		// Forward incoming metadata to the downstream call.
		md, _ := metadata.FromIncomingContext(serverStream.Context())
		outCtx := metadata.NewOutgoingContext(serverStream.Context(), md)

		clientStream, err := conn.NewStream(outCtx, &grpc.StreamDesc{
			ServerStreams: true,
			ClientStreams: true,
		}, fullMethod)
		if err != nil {
			return err
		}

		// Bidirectional forwarding.
		errCh := make(chan error, 2)

		// server→client (upstream to downstream)
		go func() {
			errCh <- forwardMessages(serverStream, clientStream)
		}()

		// client→server (downstream to upstream)
		go func() {
			errCh <- forwardMessages(clientStream, serverStream)
		}()

		// Wait for the first direction to finish (typically the client side).
		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				return err
			}
		}

		// Forward trailing metadata.
		trailer := clientStream.Trailer()
		serverStream.SetTrailer(trailer)

		return nil
	}
}

// resolveServiceID maps a gRPC full method name to a service_id using the
// generated ProxyServiceMapping.
// Full method format: "/package.Service/Method"
func resolveServiceID(fullMethod string) (string, error) {
	// Strip leading slash: "package.Service/Method"
	method := strings.TrimPrefix(fullMethod, "/")
	// Extract the package: "package" from "package.Service/Method"
	dotIdx := strings.Index(method, ".")
	if dotIdx < 0 {
		return "", fmt.Errorf("invalid method format: %s", fullMethod)
	}
	pkg := method[:dotIdx]

	serviceID, ok := routes.ProxyServiceMapping[pkg]
	if !ok {
		return "", fmt.Errorf("no service mapping for package %q", pkg)
	}
	return serviceID, nil
}

// rawMessage is a simple byte slice that implements the grpc codec interface
// for transparent proxying without unmarshaling.
type rawMessage struct {
	data []byte
}

func (r *rawMessage) Marshal() ([]byte, error)   { return r.data, nil }
func (r *rawMessage) Unmarshal(b []byte) error    { r.data = b; return nil }
func (r *rawMessage) ProtoMessage()               {}
func (r *rawMessage) Reset()                      {}
func (r *rawMessage) String() string              { return string(r.data) }

// forwardMessages reads from src and sends to dst until EOF or error.
func forwardMessages(src grpc.Stream, dst grpc.Stream) error {
	for {
		msg := &rawMessage{}
		if err := src.(interface{ RecvMsg(interface{}) error }).RecvMsg(msg); err != nil {
			if err == io.EOF {
				// Signal end of stream to the sending side.
				if cs, ok := dst.(grpc.ClientStream); ok {
					return cs.CloseSend()
				}
				return nil
			}
			zap.L().Debug("Proxy recv error", zap.Error(err))
			return err
		}
		if err := dst.(interface{ SendMsg(interface{}) error }).SendMsg(msg); err != nil {
			return err
		}
	}
}
