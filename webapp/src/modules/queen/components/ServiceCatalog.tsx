import { Collapse, Tag } from 'antd';
import type { ServiceCatalogEntry, ServiceEntitlementInfo } from '../../../../tacplus/types/services/queen/queen_pb.ts';

interface Props {
  catalog: ServiceCatalogEntry[];
  entitlements: ServiceEntitlementInfo[] | null;
}

export function ServiceCatalog({ catalog, entitlements }: Props) {
  if (!catalog.length) {
    return <div className="text-center py-6 text-gray-500">No services in catalog.</div>;
  }

  // Build a lookup: serviceName → set of granted RPCs
  const grantedMap = new Map<string, Set<string> | 'all'>();
  if (entitlements) {
    for (const e of entitlements) {
      if (e.rpcs.length === 1 && e.rpcs[0] === '*') {
        grantedMap.set(e.serviceName, 'all');
      } else if (e.rpcs.length > 0) {
        grantedMap.set(e.serviceName, new Set(e.rpcs));
      }
    }
  }

  return (
    <Collapse
      className="!bg-transparent !border-none"
      items={catalog.map((svc) => {
        const granted = grantedMap.get(svc.serviceName);
        const totalRpcs = svc.rpcs.length;

        let authorizedCount: number;
        if (!entitlements) {
          authorizedCount = -1; // unknown
        } else if (granted === 'all') {
          authorizedCount = totalRpcs;
        } else if (granted) {
          authorizedCount = svc.rpcs.filter((r) => granted.has(r)).length;
        } else {
          authorizedCount = 0;
        }

        const badgeColor = authorizedCount === -1 ? 'default' : authorizedCount === totalRpcs ? 'green' : authorizedCount > 0 ? 'orange' : 'red';
        const badgeText = authorizedCount === -1 ? `${totalRpcs} RPCs` : `${authorizedCount}/${totalRpcs} authorized`;

        return {
          key: svc.serviceName,
          label: (
            <div className="flex items-center gap-3">
              <span className="font-semibold text-slate-200">{svc.serviceName}</span>
              <Tag color={badgeColor}>{badgeText}</Tag>
            </div>
          ),
          children: (
            <div className="pl-2">
              {svc.rpcs.map((rpc) => {
                let isAuthorized: boolean | null = null;
                if (entitlements) {
                  isAuthorized = granted === 'all' || (granted instanceof Set && granted.has(rpc));
                }
                return (
                  <div key={rpc} className="flex items-center gap-2 py-1">
                    {isAuthorized !== null && (
                      <span
                        className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                        style={{ backgroundColor: isAuthorized ? '#22c55e' : '#ef4444' }}
                      />
                    )}
                    <span
                      className={`text-[13px] font-mono ${
                        isAuthorized === false ? 'text-slate-500' : 'text-slate-300'
                      }`}
                    >
                      {rpc}
                    </span>
                  </div>
                );
              })}
            </div>
          ),
          className: '!bg-[#1e293b] !border-[#334155] !mb-2 !rounded-lg',
        };
      })}
    />
  );
}
