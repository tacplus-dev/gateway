import { Table } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { AdminTokenCacheStats } from '../../../../tacplus/types/services/presley/presley_pb.ts';

interface Props {
  stats: AdminTokenCacheStats[];
}

const columns: ColumnsType<AdminTokenCacheStats> = [
  {
    title: 'Node',
    dataIndex: 'nodeId',
    key: 'nodeId',
    render: (v: string) => <span className="font-mono">{v}</span>,
  },
  { title: 'Cache Size', dataIndex: 'cacheSize', key: 'size', align: 'right', render: (v: number) => v.toLocaleString() },
  { title: 'Hits', dataIndex: 'hitCount', key: 'hits', align: 'right', render: (v: bigint) => Number(v).toLocaleString() },
  { title: 'Misses', dataIndex: 'missCount', key: 'misses', align: 'right', render: (v: bigint) => Number(v).toLocaleString() },
  {
    title: 'Hit Rate',
    key: 'rate',
    align: 'right',
    render: (_, record) => {
      const total = Number(record.hitCount) + Number(record.missCount);
      return total > 0 ? (Number(record.hitCount) / total * 100).toFixed(1) + '%' : '-';
    },
  },
  { title: 'Evictions', dataIndex: 'evictionCount', key: 'evictions', align: 'right', render: (v: bigint) => Number(v).toLocaleString() },
];

export function TokenCacheStats({ stats }: Props) {
  if (!stats.length) return null;

  return (
    <div className="mb-8">
      <h2 className="text-lg font-semibold text-slate-300 mb-3">Token Cache</h2>
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
