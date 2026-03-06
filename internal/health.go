package internal

import (
	"context"
	"fmt"
	"sync"

	healthreport_pb "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/types/libs/healthreport"
	kernel_pb "gitlab.com/secondstarcavalier/controlplane/services/gateway/tacplus/types/services/kernel"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
)

// HealthWatcher watches ServiceHealthState.instances from kernel and maintains
// an in-memory map of healthy service instances grouped by service_id.
type HealthWatcher struct {
	mu        sync.RWMutex
	services  map[string][]*healthreport_pb.ServiceInstanceHealth // service_id → healthy instances
	callbacks []func()
}

// NewHealthWatcher creates a HealthWatcher and starts watching the
// ServiceHealthState instances collection via the WatchInstances stream.
func NewHealthWatcher(ctx context.Context, stub kernel_pb.ServiceHealthStateBackendServiceClient) (*HealthWatcher, error) {
	hw := &HealthWatcher{
		services: make(map[string][]*healthreport_pb.ServiceInstanceHealth),
	}

	stream, err := stub.WatchInstances(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("start WatchInstances stream: %w", err)
	}

	go hw.receiveLoop(stream)

	return hw, nil
}

// OnChange registers a callback invoked whenever the health data changes.
func (hw *HealthWatcher) OnChange(fn func()) {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	hw.callbacks = append(hw.callbacks, fn)
}

// GetEndpoints returns the gRPC endpoints (host:port) for healthy instances
// of the given service_id. If labels is non-empty, only instances whose labels
// contain all the specified key-value pairs are returned.
func (hw *HealthWatcher) GetEndpoints(serviceID string, labels map[string]string) []string {
	hw.mu.RLock()
	defer hw.mu.RUnlock()
	instances := hw.services[serviceID]
	endpoints := make([]string, 0, len(instances))
	for _, inst := range instances {
		if !matchLabels(inst, labels) {
			continue
		}
		ep := inst.GetGrpcEndpoint()
		if ep != nil && ep.Host != "" {
			endpoints = append(endpoints, fmt.Sprintf("%s:%d", ep.Host, ep.Port))
		}
	}
	return endpoints
}

// matchLabels returns true if the instance's labels contain all required key-value pairs.
func matchLabels(inst *healthreport_pb.ServiceInstanceHealth, required map[string]string) bool {
	if len(required) == 0 {
		return true
	}
	instLabels := inst.GetLabels()
	for k, v := range required {
		if instLabels[k] != v {
			return false
		}
	}
	return true
}

// receiveLoop reads from the WatchInstances stream and rebuilds the services map.
func (hw *HealthWatcher) receiveLoop(stream kernel_pb.ServiceHealthStateBackendService_WatchInstancesClient) {
	zap.L().Info("WatchInstances receive loop started")
	for {
		msg, err := stream.Recv()
		if err != nil {
			zap.L().Warn("WatchInstances stream ended", zap.Error(err))
			return
		}

		zap.L().Info("WatchInstances received update",
			zap.Int("entries", len(msg.GetEntries())))
		hw.processEntries(msg.GetEntries())
	}
}

// processEntries rebuilds the services map from the entries snapshot.
func (hw *HealthWatcher) processEntries(entries map[string]*healthreport_pb.ServiceInstanceHealth) {
	grouped := make(map[string][]*healthreport_pb.ServiceInstanceHealth)

	for _, inst := range entries {
		if !isRoutable(inst) {
			continue
		}
		sid := inst.GetServiceId()
		grouped[sid] = append(grouped[sid], inst)
	}

	hw.mu.Lock()
	hw.services = grouped
	cbs := make([]func(), len(hw.callbacks))
	copy(cbs, hw.callbacks)
	hw.mu.Unlock()

	for sid, instances := range grouped {
		eps := make([]string, 0, len(instances))
		for _, inst := range instances {
			ep := inst.GetGrpcEndpoint()
			if ep != nil && ep.Host != "" {
				eps = append(eps, fmt.Sprintf("%s:%d", ep.Host, ep.Port))
			}
		}
		zap.L().Info("Health update",
			zap.String("service", sid),
			zap.Int("instances", len(instances)),
			zap.Strings("endpoints", eps))
	}

	for _, cb := range cbs {
		cb()
	}
}

// isRoutable returns true if the instance should receive traffic.
func isRoutable(inst *healthreport_pb.ServiceInstanceHealth) bool {
	switch inst.GetStatus() {
	case healthreport_pb.InstanceStatus_INSTANCE_STATUS_HEALTHY,
		healthreport_pb.InstanceStatus_INSTANCE_STATUS_DEGRADED:
		return true
	default:
		return false
	}
}
