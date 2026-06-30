// Data-contract tests for the workbook's Microsoft Graph (queryType 14) grids.
//
// Each Entra grid renders Graph JSON through a jsonpath transformer whose
// column paths live in the workbook JSON. These tests evaluate those *actual*
// paths (read from the shipped workbook, not a reimplementation) against canned
// Graph response elements and assert the resulting columns. This guards against
// silent column drift -- a renamed/typo'd path that would blank a column in the
// portal but pass every JSON-shape test.
//
// Run (from the repository root):
//   node --test tests/graph-transform.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const workbookPath = path.join(here, '..', 'workbook', 'third-party-vulnerabilities.workbook.json');
const workbook = JSON.parse(readFileSync(workbookPath, 'utf8'));

// --- Minimal jsonpath evaluator covering the shapes the workbook uses ---------
// Supported: $.a, $.a.b, $.a[*].b  (root $ = the Graph element / row).
function evalPath(pathExpr, obj) {
  const isMulti = pathExpr.includes('[*]');
  const parts = pathExpr.replace(/^\$\.?/, '').split('.');
  let ctx = [obj];
  for (const raw of parts) {
    const m = raw.match(/^([^[]+)(\[\*\])?$/);
    if (!m) throw new Error(`Unsupported path segment: ${raw} in ${pathExpr}`);
    const key = m[1];
    const star = Boolean(m[2]);
    const next = [];
    for (const c of ctx) {
      if (c === null || c === undefined) continue;
      const v = c[key];
      if (star) {
        if (Array.isArray(v)) next.push(...v);
      } else {
        next.push(v);
      }
    }
    ctx = next;
  }
  return isMulti ? ctx : ctx[0];
}

// Read the column map (columnid -> path) for a queryType 14 grid by item name.
function columnsFor(name) {
  const item = workbook.items.find((i) => i.name === name);
  assert.ok(item, `grid '${name}' must exist`);
  assert.equal(item.content.queryType, 14, `grid '${name}' must be a Microsoft Graph query`);
  const spec = JSON.parse(item.content.query);
  const cols = spec.transformers[0].settings.columns;
  const map = {};
  for (const c of cols) map[c.columnid] = c.path;
  return map;
}

// Apply the grid's real column paths to a fixture element -> { columnid: value }.
function project(name, element) {
  const map = columnsFor(name);
  const row = {};
  for (const [columnid, p] of Object.entries(map)) row[columnid] = evalPath(p, element);
  return row;
}

// --- Fixtures: representative Microsoft Graph response elements ----------------
const fixtures = {
  'grid-recs': {
    element: {
      displayName: 'Enable security defaults',
      priority: 'high',
      status: 'active',
      recommendationType: 'securityDefaults',
      impactType: 'tenant',
      impactStartDateTime: '2026-01-15T00:00:00Z',
      actionSteps: [{ text: 'Step one' }, { text: 'Step two' }],
    },
    expect: {
      Recommendation: 'Enable security defaults',
      Priority: 'high',
      Status: 'active',
      Type: 'securityDefaults',
      Impact: 'tenant',
      FlaggedSince: '2026-01-15T00:00:00Z',
      ActionSteps: ['Step one', 'Step two'],
    },
  },
  'grid-inventory': {
    element: {
      displayName: 'Contoso CRM',
      appId: '11111111-1111-1111-1111-111111111111',
      publisherName: 'Contoso Ltd',
      verifiedPublisher: { displayName: 'Contoso Verified' },
      appOwnerOrganizationId: '22222222-2222-2222-2222-222222222222',
      signInAudience: 'AzureADMultipleOrgs',
      accountEnabled: true,
      homepage: 'https://crm.contoso.example',
    },
    expect: {
      Application: 'Contoso CRM',
      AppId: '11111111-1111-1111-1111-111111111111',
      Publisher: 'Contoso Ltd',
      VerifiedPublisher: 'Contoso Verified',
      OwnerTenant: '22222222-2222-2222-2222-222222222222',
      Audience: 'AzureADMultipleOrgs',
      Enabled: true,
      Homepage: 'https://crm.contoso.example',
    },
  },
  'grid-creds': {
    element: {
      displayName: 'Contoso CRM',
      appId: '11111111-1111-1111-1111-111111111111',
      signInAudience: 'AzureADMyOrg',
      passwordCredentials: [
        { keyId: 'k1', endDateTime: '2026-03-01T00:00:00Z' },
        { keyId: 'k2', endDateTime: '2027-03-01T00:00:00Z' },
      ],
      keyCredentials: [{ endDateTime: '2026-12-31T00:00:00Z' }],
      createdDateTime: '2024-01-01T00:00:00Z',
    },
    expect: {
      Application: 'Contoso CRM',
      AppId: '11111111-1111-1111-1111-111111111111',
      Audience: 'AzureADMyOrg',
      ClientSecrets: ['k1', 'k2'],
      SecretExpiry: ['2026-03-01T00:00:00Z', '2027-03-01T00:00:00Z'],
      CertExpiry: ['2026-12-31T00:00:00Z'],
      Created: '2024-01-01T00:00:00Z',
    },
  },
  'grid-consents': {
    element: {
      clientId: '33333333-3333-3333-3333-333333333333',
      consentType: 'AllPrincipals',
      principalId: null,
      resourceId: '44444444-4444-4444-4444-444444444444',
      scope: 'User.Read Directory.Read.All',
    },
    expect: {
      ClientSP: '33333333-3333-3333-3333-333333333333',
      ConsentType: 'AllPrincipals',
      User: null,
      ResourceSP: '44444444-4444-4444-4444-444444444444',
      Scopes: 'User.Read Directory.Read.All',
    },
  },
  'grid-approles': {
    element: {
      principalDisplayName: 'Contoso CRM',
      principalId: '55555555-5555-5555-5555-555555555555',
      appRoleId: '19dbc75e-c2e2-444c-a770-ec69d8559fc7',
      createdDateTime: '2025-06-01T00:00:00Z',
      resourceDisplayName: 'Microsoft Graph',
    },
    expect: {
      Application: 'Contoso CRM',
      AppSP: '55555555-5555-5555-5555-555555555555',
      AppRoleId: '19dbc75e-c2e2-444c-a770-ec69d8559fc7',
      Granted: '2025-06-01T00:00:00Z',
      Resource: 'Microsoft Graph',
    },
  },
};

for (const [name, { element, expect }] of Object.entries(fixtures)) {
  test(`${name}: column paths project the expected values`, () => {
    assert.deepEqual(project(name, element), expect);
  });

  test(`${name}: every documented column is mapped (no missing/extra columns)`, () => {
    const got = Object.keys(columnsFor(name)).sort();
    const want = Object.keys(expect).sort();
    assert.deepEqual(got, want);
  });
}

test('multi-valued credential paths use array projection ([*])', () => {
  const map = columnsFor('grid-creds');
  for (const col of ['ClientSecrets', 'SecretExpiry', 'CertExpiry']) {
    assert.ok(map[col].includes('[*]'), `${col} must aggregate all credentials via [*]`);
  }
});
