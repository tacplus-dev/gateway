import { useState, useEffect, useRef } from 'react';
import { create } from '@bufbuild/protobuf';
import { SentinelServiceRestClient } from '../../../../tacplus/wrappers/restclients/rest_clients';
import type { DashboardResponse } from '../../../../tacplus/types/services/sentinel/sentinel_pb.ts';
import { WatchDashboardRequestSchema } from '../../../../tacplus/types/services/sentinel/sentinel_pb.ts';
import { fetchTransport } from '../../../auth/fetchTransport';

const sentinel = new SentinelServiceRestClient(fetchTransport, '');

export function useDashboard() {
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const retriesRef = useRef(0);

  useEffect(() => {
    const controller = new AbortController();
    let stopped = false;

    async function startStream() {
      try {
        const stream = await sentinel.watchDashboard(
          create(WatchDashboardRequestSchema, { intervalSeconds: 5 }),
          { signal: controller.signal },
        );
        retriesRef.current = 0;
        for await (const update of stream) {
          if (stopped) break;
          setData(update);
          setError(null);
          setLoading(false);
        }
        // Stream ended normally — server closed it
        if (!stopped) {
          setError('Stream ended');
        }
      } catch (err) {
        if (stopped || controller.signal.aborted) return;
        const msg = err instanceof Error ? err.message : 'Network error';
        if (msg.includes('401') || msg.includes('403')) {
          setError(msg.includes('401') ? 'Unauthorized' : 'Forbidden');
          setLoading(false);
          return; // don't retry auth errors
        }
        setError(msg);
        setLoading(false);
        // Reconnect with backoff
        const delay = Math.min(1000 * 2 ** retriesRef.current, 30000);
        retriesRef.current++;
        await new Promise((r) => setTimeout(r, delay));
        if (!stopped) startStream();
      }
    }

    startStream();
    return () => {
      stopped = true;
      controller.abort();
    };
  }, []);

  return { data, error, loading };
}
