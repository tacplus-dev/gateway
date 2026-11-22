// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The fleet's modules, read from the gateway's /-/apps.json.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fleetApps } from '../src/apps.ts';

const serving = (status: number, body: unknown) => {
  const asked: string[] = [];
  const fetchFn = (async (url: string) => {
    asked.push(url);
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { asked, fetchFn };
};

const ECHO = { service: 'tenantecho', title: 'Echo', version: '1.2.0', path: '/-/apps/tenantecho/' };
const PAGER = { service: 'pager', title: 'Pager', version: '0.3.1', path: '/-/apps/pager/' };

test('the modules are the index the gateway serves, in its order', async () => {
  const { asked, fetchFn } = serving(200, [PAGER, ECHO]);
  assert.deepEqual(await fleetApps(fetchFn), [PAGER, ECHO]);
  assert.deepEqual(asked, ['/-/apps.json']);
});

test('no index is no modules', async () => {
  assert.deepEqual(await fleetApps(serving(404, 'not found').fetchFn), []);
});

test('a gateway that fails says so', async () => {
  await assert.rejects(fleetApps(serving(502, 'bad gateway').fetchFn), /502/);
});

// A module is mounted at its service's own path; an entry naming any other
// (another origin, a script URL, someone else's mount) is not linked.
test('an entry whose path is not its own mount is dropped', async () => {
  const entries = [
    ECHO,
    { ...PAGER, path: 'javascript:alert(1)' },
    { ...PAGER, path: 'https://evil.example/' },
    { ...PAGER, path: '/-/apps/tenantecho/' },
    { ...PAGER, service: '../x', path: '/-/apps/../x/' },
    { service: 'pager', path: '/-/apps/pager/' },
    'pager',
  ];
  assert.deepEqual(await fleetApps(serving(200, entries).fetchFn), [ECHO]);
});

test('an index that is not a list is no modules', async () => {
  assert.deepEqual(await fleetApps(serving(200, { apps: [ECHO] }).fetchFn), []);
});
