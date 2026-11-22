// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The webapp modules the fleet's services contribute to its gateway, each
// served at /-/apps/<service>/ on the gateway's origin (tacplus docs/USER.md,
// "Contributing to the gateway"; gateway#21).

/** One entry of the gateway's /-/apps.json, written by the fleet builder. */
export interface FleetApp {
  /** The contributing service's registry name. */
  service: string;
  /** Its title in the index. */
  title: string;
  /** The service's release the module was built from. */
  version: string;
  /** Where it is served: always /-/apps/<service>/. */
  path: string;
}

const NAME = /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/;

/** A module is mounted at its service's own path, which no contributor
 * chooses; an entry naming any other is not one to link to. */
function isFleetApp(e: unknown): e is FleetApp {
  if (typeof e !== 'object' || e === null) return false;
  const a = e as Record<string, unknown>;
  return typeof a.service === 'string' && NAME.test(a.service)
    && typeof a.title === 'string' && typeof a.version === 'string'
    && a.path === `/-/apps/${a.service}/`;
}

/** The fleet's modules, in the index's order (sorted by service). A gateway
 * with no index (404) has none; any other failure is thrown. */
export async function fleetApps(fetchFn: typeof fetch = fetch): Promise<FleetApp[]> {
  const resp = await fetchFn('/-/apps.json');
  if (resp.status === 404) return [];
  if (!resp.ok) throw new Error(`/-/apps.json: ${resp.status}`);
  const index: unknown = await resp.json();
  return Array.isArray(index) ? index.filter(isFleetApp) : [];
}
