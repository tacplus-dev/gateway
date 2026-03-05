package internal

import (
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc/resolver"
)

const resolverScheme = "health"

// HealthResolver implements grpc/resolver.Builder and integrates with
// HealthWatcher to push healthy endpoints to gRPC's built-in load balancer.
type HealthResolver struct {
	hw        *HealthWatcher
	mu        sync.Mutex
	resolvers map[string][]*healthResolverInstance // service_id → active resolvers
}

// NewHealthResolver creates a HealthResolver and registers it as the default
// resolver for the "health" scheme. Downstream connections use targets like
// "health:///fleetwood".
func NewHealthResolver(hw *HealthWatcher) *HealthResolver {
	hr := &HealthResolver{
		hw:        hw,
		resolvers: make(map[string][]*healthResolverInstance),
	}

	resolver.Register(hr)

	hw.OnChange(func() {
		hr.pushAll()
	})

	return hr
}

// Build implements resolver.Builder. Called by gRPC when dialing a health:/// target.
func (hr *HealthResolver) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	serviceID := target.Endpoint()

	inst := &healthResolverInstance{
		hr:        hr,
		serviceID: serviceID,
		cc:        cc,
	}

	hr.mu.Lock()
	hr.resolvers[serviceID] = append(hr.resolvers[serviceID], inst)
	hr.mu.Unlock()

	// Push current state immediately.
	inst.push()

	return inst, nil
}

// Scheme implements resolver.Builder.
func (hr *HealthResolver) Scheme() string {
	return resolverScheme
}

// pushAll pushes updated addresses to all active resolver instances.
func (hr *HealthResolver) pushAll() {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	for _, instances := range hr.resolvers {
		for _, inst := range instances {
			inst.push()
		}
	}
}

// remove unregisters a resolver instance.
func (hr *HealthResolver) remove(inst *healthResolverInstance) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	list := hr.resolvers[inst.serviceID]
	for i, r := range list {
		if r == inst {
			hr.resolvers[inst.serviceID] = append(list[:i], list[i+1:]...)
			break
		}
	}
}

// healthResolverInstance is a per-target resolver.Resolver that pushes
// addresses from HealthWatcher to a single ClientConn.
type healthResolverInstance struct {
	hr        *HealthResolver
	serviceID string
	cc        resolver.ClientConn
}

// push queries HealthWatcher for current endpoints and pushes them to gRPC.
func (r *healthResolverInstance) push() {
	endpoints := r.hr.hw.GetEndpoints(r.serviceID)
	addrs := make([]resolver.Address, len(endpoints))
	for i, ep := range endpoints {
		addrs[i] = resolver.Address{Addr: ep}
	}

	if err := r.cc.UpdateState(resolver.State{Addresses: addrs}); err != nil {
		zap.L().Warn("Failed to update resolver state",
			zap.String("service", r.serviceID),
			zap.Error(err))
	}
}

// ResolveNow implements resolver.Resolver. gRPC calls this when it wants
// a refresh; we push current health data.
func (r *healthResolverInstance) ResolveNow(resolver.ResolveNowOptions) {
	r.push()
}

// Close implements resolver.Resolver.
func (r *healthResolverInstance) Close() {
	r.hr.remove(r)
}
