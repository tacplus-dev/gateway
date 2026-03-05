import { useState, useEffect, useRef, useCallback, useContext } from 'react';
import { Tabs, Spin, Alert } from 'antd';
import { create } from '@bufbuild/protobuf';
import { PolicyServiceRestClient } from '../../../../tacplus/wrappers/restclients/rest_clients';
import { SimulateEntitlementsRequestSchema } from '../../../../tacplus/types/services/policy/policy_pb.ts';
import type {
  ServiceCatalogEntry,
  ServiceEntitlementInfo,
} from '../../../../tacplus/types/services/policy/policy_pb.ts';
import type { OpaPolicy } from '../../../../tacplus/libs/opa/opa_pb.ts';
import { AuthContext } from '../../../auth/AuthContext';
import { fetchTransport } from '../../../auth/fetchTransport';
import { getStoredToken } from '../../../auth/tokenUtils';
import { ServiceCatalog } from './ServiceCatalog';
import { TokenEditor } from './TokenEditor';
import { PolicyEditor } from './PolicyEditor';

const policyClient = new PolicyServiceRestClient(fetchTransport, '');

function base64UrlDecode(s: string): string {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  return atob(padded);
}

function parseJwtParts(token: string): { header: string; payload: string } | null {
  try {
    const parts = token.trim().split('.');
    if (parts.length < 2) return null;
    const header = JSON.stringify(JSON.parse(base64UrlDecode(parts[0])), null, 2);
    const payload = JSON.stringify(JSON.parse(base64UrlDecode(parts[1])), null, 2);
    return { header, payload };
  } catch {
    return null;
  }
}

export function Dashboard() {
  const [activeTab, setActiveTab] = useState('catalog');
  const { accessToken } = useContext(AuthContext);

  // Catalog data
  const [catalog, setCatalog] = useState<ServiceCatalogEntry[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const [catalogError, setCatalogError] = useState<string | null>(null);

  // Entitlements from simulation
  const [entitlements, setEntitlements] = useState<ServiceEntitlementInfo[] | null>(null);
  const [simError, setSimError] = useState<string | null>(null);
  const [simLoading, setSimLoading] = useState(false);

  // Token editor state
  const realToken = getStoredToken() || '';
  const initialParts = parseJwtParts(realToken);
  const [headerJson, setHeaderJson] = useState(initialParts?.header || '{}');
  const [payloadJson, setPayloadJson] = useState(initialParts?.payload || '{}');
  const defaultHeaderRef = useRef(initialParts?.header || '{}');
  const defaultPayloadRef = useRef(initialParts?.payload || '{}');

  // Policy editor state
  const [entitlementsPolicy, setEntitlementsPolicy] = useState<OpaPolicy | null>(null);
  const [claimMappingPolicy, setClaimMappingPolicy] = useState<OpaPolicy | null>(null);
  const [policiesLoading, setPoliciesLoading] = useState(true);
  const [policiesError, setPoliciesError] = useState<string | null>(null);

  // Debounce timer
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Simulate entitlements using current payload
  const runSimulation = useCallback(async (payload: string) => {
    setSimLoading(true);
    setSimError(null);
    try {
      let claims: Record<string, unknown>;
      try {
        claims = JSON.parse(payload);
      } catch {
        throw new Error('Invalid payload JSON');
      }
      const data = await policyClient.simulateEntitlements(
        create(SimulateEntitlementsRequestSchema, { claimsJson: JSON.stringify(claims) }),
      );
      setEntitlements([...data.entitlements]);
    } catch (err) {
      setSimError(err instanceof Error ? err.message : 'Simulation failed');
    } finally {
      setSimLoading(false);
    }
  }, []);

  // Debounced simulation trigger
  const debouncedSimulate = useCallback(
    (payload: string) => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => runSimulation(payload), 500);
    },
    [runSimulation],
  );

  // On mount: fetch catalog + policies + initial simulation
  useEffect(() => {
    policyClient
      .getServiceCatalog()
      .then((data) => {
        setCatalog(data.services);
        setCatalogError(null);
      })
      .catch((err) => setCatalogError(err.message))
      .finally(() => setCatalogLoading(false));

    policyClient
      .getPolicies()
      .then((data) => {
        setEntitlementsPolicy(data.entitlementsPolicy ?? null);
      })
      .catch((err) => setPoliciesError(err instanceof Error ? err.message : 'Failed to load policies'))
      .finally(() => setPoliciesLoading(false));

    // Initial simulation with real token payload
    if (initialParts?.payload) {
      runSimulation(initialParts.payload);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Re-run simulation when payload changes
  const handlePayloadChange = useCallback(
    (newPayload: string) => {
      setPayloadJson(newPayload);
      debouncedSimulate(newPayload);
    },
    [debouncedSimulate],
  );

  const handleTokenReset = useCallback(() => {
    const token = getStoredToken() || '';
    const parts = parseJwtParts(token);
    if (parts) {
      setHeaderJson(parts.header);
      setPayloadJson(parts.payload);
      defaultHeaderRef.current = parts.header;
      defaultPayloadRef.current = parts.payload;
      runSimulation(parts.payload);
    }
  }, [runSimulation]);

  if (catalogLoading) {
    return (
      <div className="max-w-[1400px] mx-auto px-6 py-4">
        <div className="text-center py-12"><Spin tip="Loading..." /></div>
      </div>
    );
  }

  return (
    <div className="max-w-[1400px] mx-auto px-6 py-4">
      <header className="flex items-baseline gap-4 mb-4 border-b border-[#333] pb-3">
        <h1 className="m-0 text-[28px] font-bold text-white">API &amp; Entitlements</h1>
        {simLoading && <Spin size="small" />}
      </header>

      {catalogError && <Alert type="error" message={`Catalog: ${catalogError}`} showIcon className="mb-4" />}
      {policiesError && <Alert type="error" message={`Policy: ${policiesError}`} showIcon className="mb-4" />}
      {simError && <Alert type="warning" message={`Simulation: ${simError}`} showIcon closable className="mb-4" />}

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'catalog',
            label: 'API Catalog',
            children: <ServiceCatalog catalog={catalog} entitlements={entitlements} />,
          },
          {
            key: 'token',
            label: 'Token',
            children: (
              <TokenEditor
                headerJson={headerJson}
                payloadJson={payloadJson}
                onHeaderChange={setHeaderJson}
                onPayloadChange={handlePayloadChange}
                onReset={handleTokenReset}
              />
            ),
          },
          {
            key: 'policy',
            label: 'Policy',
            children: (
              <PolicyEditor
                entitlementsPolicy={entitlementsPolicy}
                claimMappingPolicy={claimMappingPolicy}
                loading={policiesLoading}
              />
            ),
          },
        ]}
      />
    </div>
  );
}
