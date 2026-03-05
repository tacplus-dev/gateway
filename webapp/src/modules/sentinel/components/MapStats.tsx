import { Table, Tag } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { AdminMapStats } from '../../../../tacplus/types/services/presley/presley_pb.ts';

interface Props {
  stats: AdminMapStats[];
}

function formatBytes(bytes: bigint | number | string): string {
  const n = Number(bytes);
  if (!n || isNaN(n)) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function num(v: bigint | number | string | undefined): string {
  if (v === undefined || v === null || v === '') return '0';
  const n = Number(v);
  return isNaN(n) ? '0' : n.toLocaleString();
}

function graphTypeLabel(gt: number): string {
  switch (gt) {
    case 0: return 'Singleton';
    case 1: return 'Collection';
    case 2: return 'Queue';
    case 3: return 'Priority Queue';
    case 4: return 'Topic';
    case 5: return 'View';
    case 6: return 'Command';
    default: return 'Unknown';
  }
}

function groupByGraphType(stats: AdminMapStats[]): Map<number, AdminMapStats[]> {
  const groups = new Map<number, AdminMapStats[]>();
  for (const s of stats) {
    const gt = s.graphType ?? 1;
    if (!groups.has(gt)) groups.set(gt, []);
    groups.get(gt)!.push(s);
  }
  return groups;
}

const columns: ColumnsType<AdminMapStats> = [
  {
    title: 'Map Name',
    dataIndex: 'mapName',
    key: 'mapName',
    render: (name: string, record) => (
      <span className="font-mono text-slate-200" title={record.qualifiedName || name}>{name}</span>
    ),
    sorter: (a, b) => a.mapName.localeCompare(b.mapName),
    defaultSortOrder: 'ascend',
  },
  {
    title: 'Value Type',
    dataIndex: 'valueType',
    key: 'valueType',
    render: (v: string) => <span className="font-mono text-gray-500 text-xs">{v || '\u2014'}</span>,
  },
  {
    title: 'Properties',
    key: 'props',
    render: (_, record) => (
      <div className="flex gap-1 flex-wrap">
        {record.consistency && (
          <Tag color={record.consistency === 'atomic' ? 'cyan' : 'orange'}>{record.consistency}</Tag>
        )}
        {record.persistence && <Tag color="green">persisted</Tag>}
      </div>
    ),
  },
  { title: 'Entries', dataIndex: 'size', key: 'size', align: 'right', render: (v: number) => num(v) },
  { title: 'Owned', dataIndex: 'ownedEntryCount', key: 'owned', align: 'right', render: (v: number) => num(v) },
  { title: 'Backups', dataIndex: 'backupEntryCount', key: 'backups', align: 'right', render: (v: number) => num(v) },
  { title: 'Heap Cost', dataIndex: 'heapCostBytes', key: 'heap', align: 'right', render: (v: number) => formatBytes(v) },
  { title: 'Puts', dataIndex: 'putCount', key: 'puts', align: 'right', render: (v: number) => num(v) },
  { title: 'Gets', dataIndex: 'getCount', key: 'gets', align: 'right', render: (v: number) => num(v) },
  { title: 'Removes', dataIndex: 'removeCount', key: 'removes', align: 'right', render: (v: number) => num(v) },
  { title: 'Hits', dataIndex: 'hitCount', key: 'hits', align: 'right', render: (v: number) => num(v) },
  { title: 'Evictions', dataIndex: 'evictionCount', key: 'evictions', align: 'right', render: (v: number) => num(v) },
  { title: 'Locked', dataIndex: 'lockedEntryCount', key: 'locked', align: 'right', render: (v: number) => num(v) },
];

const GRAPH_TYPE_ORDER = [0, 1, 2, 3, 4, 5, 6];

export function MapStats({ stats }: Props) {
  if (!stats.length) return null;

  const groups = groupByGraphType(stats);
  const totalHeap = stats.reduce((sum, s) => sum + Number(s.heapCostBytes), 0);
  const totalEntries = stats.reduce((sum, s) => sum + (s.size || 0), 0);

  return (
    <div className="mb-8">
      <h2 className="text-lg font-semibold text-slate-300 mb-4">
        Map Statistics ({stats.length} maps, {totalEntries.toLocaleString()} entries, {formatBytes(totalHeap)} total heap)
      </h2>
      {GRAPH_TYPE_ORDER.filter((gt) => groups.has(gt)).map((gt) => {
        const maps = groups.get(gt)!;
        const label = graphTypeLabel(gt);
        const groupHeap = maps.reduce((sum, s) => sum + Number(s.heapCostBytes), 0);
        return (
          <div key={gt} className="mb-6">
            <h3 className="text-sm font-semibold text-slate-400 mb-2 flex items-center gap-2.5">
              {label}s
              <span className="text-xs font-normal text-gray-600">
                {maps.length} {maps.length === 1 ? 'map' : 'maps'}, {formatBytes(groupHeap)}
              </span>
            </h3>
            <Table
              columns={columns}
              dataSource={maps}
              rowKey="mapName"
              size="small"
              pagination={false}
              scroll={{ x: true }}
              className="[&_.ant-table]:!bg-[#1e1e1e] [&_.ant-table-thead>tr>th]:!bg-[#1e1e1e] [&_.ant-table-tbody>tr>td]:!border-b-[#2a2a2a]"
            />
          </div>
        );
      })}
    </div>
  );
}
