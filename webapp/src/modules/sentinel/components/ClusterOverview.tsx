import { Card, Tag } from 'antd';
import type { AdminClusterInfo, AdminClusterHealth } from '../../../../tacplus/types/services/presley/presley_pb.ts';

interface Props {
  info?: AdminClusterInfo;
  health?: AdminClusterHealth;
}

export function ClusterOverview({ info, health }: Props) {
  if (!info || !health) return null;

  const isSafe = health.clusterSafe && health.hasQuorum;

  return (
    <div className="mb-8">
      <h2 className="text-lg font-semibold text-slate-300 mb-3">Cluster Overview</h2>
      <div className="grid grid-cols-2 gap-4">
        <Card size="small" className="!bg-[#1e1e1e] !border-[#333]">
          <div className="text-sm font-semibold text-slate-400 mb-3">Cluster Info</div>
          <StatRow label="Name" value={info.clusterName || 'N/A'} />
          <StatRow label="State" value={info.state || 'N/A'} valueColor={health.running ? '#4caf50' : '#ff9800'} />
          <StatRow label="Version" value={info.version || 'N/A'} />
          <StatRow label="Size" value={`${info.clusterSize} nodes`} />
          <StatRow label="Partitions" value={String(info.partitionCount)} />
        </Card>

        <Card size="small" className="!bg-[#1e1e1e] !border-[#333]">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-400 mb-3">
            Health
            <Tag color={isSafe ? 'success' : 'error'}>{isSafe ? 'SAFE' : 'UNSAFE'}</Tag>
          </div>
          <StatRow label="Running" value={health.running ? 'Yes' : 'No'} valueColor={health.running ? '#4caf50' : '#f44336'} />
          <StatRow label="Quorum" value={health.hasQuorum ? 'Yes' : 'No'} valueColor={health.hasQuorum ? '#4caf50' : '#f44336'} />
          <StatRow label="Migration Queue" value={String(health.migrationQueueSize)} />
          <StatRow label="Cluster State" value={health.clusterState || 'N/A'} />
        </Card>

        <Card size="small" className="!bg-[#1e1e1e] !border-[#333] col-span-2">
          <div className="text-sm font-semibold text-slate-400 mb-3">Members ({info.members?.length || 0})</div>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
            {[...(info.members || [])].sort((a, b) => a.uuid.localeCompare(b.uuid)).map((m) => (
              <div key={m.uuid} className="bg-[#252525] rounded p-2 text-xs">
                <div className="font-mono text-slate-200 mb-1">{m.address}</div>
                <div className="flex gap-1.5 items-center">
                  {m.isLocal && <span className="text-[9px] font-bold px-1 rounded-sm bg-[#1b5e20] text-[#81c784]">LOCAL</span>}
                  {m.lite && <span className="text-[9px] font-bold px-1 rounded-sm bg-[#4a148c] text-[#ce93d8]">LITE</span>}
                  <span className="text-gray-500 font-mono text-[10px]">{m.uuid.slice(0, 8)}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

function StatRow({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div className="flex justify-between py-1 text-[13px]">
      <span className="text-gray-500">{label}</span>
      <span className="font-mono text-slate-200" style={valueColor ? { color: valueColor } : undefined}>{value}</span>
    </div>
  );
}
