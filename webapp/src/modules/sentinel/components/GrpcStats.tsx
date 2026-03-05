import { Table } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { AdminGrpcStats } from '../../../../tacplus/types/services/presley/presley_pb.ts';

interface Props {
  stats: AdminGrpcStats[];
}

const columns: ColumnsType<AdminGrpcStats> = [
  {
    title: 'Node',
    dataIndex: 'nodeId',
    key: 'nodeId',
    render: (v: string) => <span className="font-mono">{v}</span>,
  },
  { title: 'Active Conns', dataIndex: 'activeConnections', key: 'conns', align: 'right' },
  { title: 'Active RPCs', dataIndex: 'activeRpcs', key: 'rpcs', align: 'right' },
  { title: 'Total RPCs', dataIndex: 'totalRpcs', key: 'totalRpcs', align: 'right', render: (v: bigint) => Number(v).toLocaleString() },
  { title: 'Active Streams', dataIndex: 'activeStreams', key: 'streams', align: 'right' },
  { title: 'Rate Limited', dataIndex: 'rateLimitedCount', key: 'limited', align: 'right', render: (v: bigint) => Number(v).toLocaleString() },
];

export function GrpcStats({ stats }: Props) {
  if (!stats.length) return null;

  return (
    <div className="mb-8">
      <h2 className="text-lg font-semibold text-slate-300 mb-3">gRPC Statistics</h2>
      <Table
        columns={columns}
        dataSource={stats}
        rowKey="nodeId"
        size="small"
        pagination={false}
        className="[&_.ant-table]:!bg-[#1e1e1e] [&_.ant-table-thead>tr>th]:!bg-[#1e1e1e] [&_.ant-table-tbody>tr>td]:!border-b-[#2a2a2a]"
      />
    </div>
  );
}
