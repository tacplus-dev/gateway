import { useState } from 'react';
import { Alert, Button, Spin } from 'antd';
import { useDashboard } from '../hooks/useREST';
import { ClusterOverview } from './ClusterOverview';
import { NodeMetrics } from './NodeMetrics';
import { GrpcStats } from './GrpcStats';
import { TokenCacheStats } from './TokenCacheStats';
import { MapStats } from './MapStats';

export function Dashboard() {
  const { data, error, loading } = useDashboard();
  const [dismissed, setDismissed] = useState(false);
  const isAuthError = error === 'Unauthorized' || error === 'Forbidden' || error?.startsWith('Not authorized');

  return (
    <div className="max-w-[1400px] mx-auto px-6 py-4">
      <header className="flex items-baseline gap-4 mb-6 border-b border-[#333] pb-3">
        <h1 className="m-0 text-[28px] font-bold text-white">Health & Metrics</h1>
        {loading && <Spin size="small" className="ml-auto" />}
      </header>

      {isAuthError && !dismissed && (
        <Alert
          type="info"
          message="Not Authorized"
          description="You do not have authorization to access this service."
          showIcon
          className="mb-4"
          action={<Button size="small" onClick={() => setDismissed(true)}>Dismiss</Button>}
        />
      )}

      {error && !isAuthError && (
        <Alert type="error" message={error} showIcon className="mb-4" />
      )}

      {data && (
        <>
          <ClusterOverview info={data.clusterInfo} health={data.clusterHealth} />
          <NodeMetrics
            metrics={data.nodeMetrics || []}
            persistence={data.persistenceStatus || []}
            network={data.networkStats || []}
          />
          <GrpcStats stats={data.grpcStats || []} />
          <TokenCacheStats stats={data.tokenCacheStats || []} />
          <MapStats stats={data.mapStats || []} />
        </>
      )}

      {!data && !loading && !error && (
        <div className="text-center py-12 text-gray-500 text-base">
          No data available. Is elvis running?
        </div>
      )}
    </div>
  );
}
