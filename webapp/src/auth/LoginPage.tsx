import { useState, useEffect } from 'react';
import { Card, Button, Alert, Spin } from 'antd';
import { create } from '@bufbuild/protobuf';
import { IronMaidenServiceRestClient } from '../../tacplus/wrappers/restclients/rest_clients';
import { AuthorizeRequestSchema } from '../../tacplus/types/services/ironmaiden/ironmaiden_pb.ts';
import type { ProviderInfo } from '../../tacplus/types/services/ironmaiden/ironmaiden_pb.ts';
import { publicTransport } from './fetchTransport';

const ironmaiden = new IronMaidenServiceRestClient(publicTransport, '');

export function LoginPage() {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    ironmaiden
      .listProviders()
      .then((data) => {
        setProviders(data.providers);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const handleLogin = async (providerIndex: number) => {
    try {
      const callbackUrl = window.location.origin + '/';
      const data = await ironmaiden.authorize(
        create(AuthorizeRequestSchema, {
          providerIndex,
          callbackUrl,
        }),
      );
      if (data.redirectUrl) {
        window.location.href = data.redirectUrl;
      } else {
        setError('No redirect URL received from server');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to initiate login');
    }
  };

  return (
    <div className="flex justify-center items-center min-h-screen bg-[#0f172a]">
      <Card className="!bg-[#1e293b] !border-[#334155] w-full max-w-[400px]">
        <div className="text-center">
          <div className="flex items-center justify-center gap-3 mb-2">
            <img src="/logo-icon.svg" alt="Cavalier" className="w-7 h-[30px]" />
            <h1 className="text-[28px] font-bold text-slate-50 m-0">Cavalier</h1>
          </div>
          <p className="text-sm text-slate-400 mb-8">Sign in to continue</p>

          {error && <Alert type="error" message={error} showIcon className="mb-4 text-left" />}

          {loading && (
            <div className="py-5">
              <Spin tip="Loading providers..." />
            </div>
          )}

          <div className="flex flex-col gap-3">
            {providers.map((p) => (
              <Button
                key={p.providerIndex}
                size="large"
                block
                onClick={() => handleLogin(p.providerIndex)}
                className="!border-[#334155] !text-sky-400 hover:!border-sky-400"
              >
                Sign in with {p.name}
              </Button>
            ))}
          </div>

          {!loading && providers.length === 0 && !error && (
            <p className="text-slate-500 text-sm py-5">No authentication providers configured.</p>
          )}
        </div>
      </Card>
    </div>
  );
}
