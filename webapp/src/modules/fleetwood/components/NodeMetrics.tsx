import { Card, Progress } from 'antd';
import type { AdminNodeMetrics, AdminPersistenceStatus, AdminNetworkStats } from '../../../../tacplus/types/services/presley/presley_pb.ts';

interface Props {
  metrics: AdminNodeMetrics[];
  persistence: AdminPersistenceStatus[];
  network: AdminNetworkStats[];
}

function formatBytes(bytes: bigint | number | string): string {
  const n = Number(bytes);
  if (!n || isNaN(n)) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function formatUptime(ms: bigint | number | string): string {
  const n = Number(ms);
  if (!n || isNaN(n)) return '0s';
  const hours = Math.floor(n / 3600000);
  const mins = Math.floor((n % 3600000) / 60000);
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function pct(used: bigint | number | string, max: bigint | number | string): number {
  const u = Number(used);
  const m = Number(max);
  if (!m || isNaN(m) || m === 0) return 0;
  return Math.round((u / m) * 100);
}

function barColor(value: number): string {
  if (value > 85) return '#f44336';
  if (value > 60) return '#ff9800';
  return '#4caf50';
}

export function NodeMetrics({ metrics, persistence, network }: Props) {
  const persistMap = new Map(persistence.map((p) => [p.nodeId, p]));
  const netMap = new Map(network.map((n) => [n.nodeId, n]));

  return (
    <div className="mb-8">
      <h2 className="text-lg font-semibold text-slate-300 mb-3">Node Metrics</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(340px,1fr))] gap-4">
        {metrics.map((node) => {
          const heapPct = pct(node.memory?.heapUsedBytes ?? 0, node.memory?.heapMaxBytes ?? 0);
          const diskTotal = Number(node.disk?.totalBytes ?? 0);
          const diskUsable = Number(node.disk?.usableBytes ?? 0);
          const diskPct = diskTotal > 0 ? Math.round(((diskTotal - diskUsable) / diskTotal) * 100) : 0;
          const cpuPct = Math.round((node.cpu?.processCpuLoad || 0) * 100);
          const pers = persistMap.get(node.nodeId);
          const net = netMap.get(node.nodeId);

          return (
            <Card key={node.nodeId} size="small" className="!bg-[#1e1e1e] !border-[#333]">
              <div className="text-sm font-semibold text-slate-400 mb-3 font-mono">{node.nodeId}</div>

              <div className="mb-2.5">
                <div className="text-[11px] text-gray-500 mb-1">Heap</div>
                <Progress percent={heapPct} strokeColor={barColor(heapPct)} trailColor="#2a2a2a" size="small" />
                <div className="text-[10px] text-gray-600">
                  {formatBytes(node.memory?.heapUsedBytes ?? 0)} / {formatBytes(node.memory?.heapMaxBytes ?? 0)}
                </div>
              </div>

              <div className="mb-2.5">
                <div className="text-[11px] text-gray-500 mb-1">CPU</div>
                <Progress percent={cpuPct} strokeColor={cpuPct > 85 ? '#f44336' : cpuPct > 60 ? '#ff9800' : '#2196f3'} trailColor="#2a2a2a" size="small" />
                <div className="text-[10px] text-gray-600">
                  {node.cpu?.availableProcessors} cores &middot; uptime {formatUptime(node.cpu?.uptimeMs ?? 0)}
                </div>
              </div>

              <div className="mb-2.5">
                <div className="text-[11px] text-gray-500 mb-1">Disk</div>
                <Progress percent={diskPct} strokeColor={barColor(diskPct)} trailColor="#2a2a2a" size="small" />
                <div className="text-[10px] text-gray-600">
                  {formatBytes(node.disk?.usableBytes ?? 0)} free / {formatBytes(node.disk?.totalBytes ?? 0)}
                </div>
              </div>

              {node.memory && (
                <div className="text-[11px] text-gray-500 py-0.5 border-t border-[#2a2a2a] mt-1">
                  GC: {Number(node.memory.gcCount)} runs, {Number(node.memory.gcTimeMs)}ms total
                </div>
              )}
              {pers && (
                <div className="text-[11px] text-gray-500 py-0.5 border-t border-[#2a2a2a]">
                  Persistence: {pers.enabled ? 'ON' : 'OFF'}
                  {pers.enabled && ` | Redo: ${Number(pers.redoLogEntryCount)} entries`}
                  {pers.enabled && ` | Dumps: ${Number(pers.dumpCount)}`}
                </div>
              )}
              {net && (
                <div className="text-[11px] text-gray-500 py-0.5 border-t border-[#2a2a2a]">
                  Net: {formatBytes(net.bytesSent)} sent, {formatBytes(net.bytesReceived)} recv
                  {' | '}{net.activeGrpcConnections} gRPC conns
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
