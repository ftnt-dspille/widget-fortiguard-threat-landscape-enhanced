'use strict';
// E2E for the reworked FortiGuard Threat Landscape view. The connector's
// integration endpoints are stubbed at the browser level (page.route) with
// payloads shaped like the live feed, so the hermetic tier sees no
// un-stubbed proxy call. Assertions are on DOM and text, never computed
// colors.
//
//   make test-e2e-spec WIDGET=fortiGuardThreatLandscape

const { test, expect } = require('../../../../fortisoar-widget-harness/tests/e2e/_fixtures');
const { mountWidget } = require('../../../../fortisoar-widget-harness/tests/e2e/_widgetHarness');

const LOGTIME = '2026-11-19 00:44';

function statsEnv(rows) {
  return [{ Logtime: LOGTIME, Stats: rows }];
}

// Counts scale with the window like the feed's cumulative totals do, so the
// daily rates come out flat and the sparkline is deterministic.
const CARD_BASE = {
  'Malicious Activity Detected': 8.6e9,
  'Intrusion Prevention Activity': 8.0e9,
  'Malware Distribution Activity': 1.5e8,
  'Botnet Activity Detected': 1.0e7,
  'Endpoint Activity Detected': 1.1e8
};

function fixtureData(op, params) {
  params = params || {};
  const win = Number(params.time_windows || 7);
  if (op.indexOf('threat_activities_statistics') === 0) {
    const base = CARD_BASE[params.threat_type] || 1e6;
    return statsEnv([{ Count: Math.round(base * win / 7), Threattype: params.threat_type, trend: win === 21 ? null : { percentage: '1.5', direction: 'up' } }]);
  }
  if (op.indexOf('kill_chain_metrics') === 0) {
    return [
      { id: 'reconnaissance', title: 'Reconnaissance', metrics: [{ Threattype: 'ips', Threat_category: 'ActiveScan', Count: 51168776659 }] },
      { id: 'weaponization', title: 'Weaponization', metrics: [] },
      { id: 'delivery', title: 'Delivery', metrics: [{ Threattype: 'virus', Threat_category: 'DriveByDownload', Count: 3851716 }] },
      { id: 'exploitation', title: 'Exploitation', metrics: [{ Threattype: 'ips', Threat_category: 'BruteForce', Count: 935141439 }] },
      { id: 'installation', title: 'Installation', metrics: [{ Threattype: 'virus', Threat_category: 'Trojans', Count: 18660493 }] },
      { id: 'command-and-control', title: 'Command & Control', metrics: [] },
      { id: 'actions-on-objectives', title: 'Actions on Objectives', metrics: [{ Threattype: 'virus', Threat_category: 'Ranswomware', Count: 125717 }] }
    ];
  }
  if (op.indexOf('top_threats') === 0) {
    const virus = params.threat_type === 'Malware';
    const names = virus
      ? ['W32/BackDoor.Prosiak', 'HTML/Phish.Tag', 'MSExcel/CVE_2017_0199', 'PossibleThreat.RF', 'Riskware/CoinMiner']
      : ['DNS.PTR.Records.Scan', 'HTTP.Suspicious.Headers', 'SIPVicious.SIP.Scanner', 'Modbus.TCP.Unauthorized.Read', 'TCP.Out.Of.Range.Timestamp'];
    return statsEnv(names.map((n, i) => ({ Name: n, ID: 1000 + i, Threattype: virus ? 'virus' : 'ips', Count: Math.round(1e9 / (i + 1)) })));
  }
  if (op === 'top_threat_countries' || op === 'top_countries_industry') {
    return statsEnv(['US', 'VN', 'IN', 'NZ', 'CH', 'ID'].map((c, i) => ({ Country: c, Threattype: 'ips', Count: Math.round(1e10 / (i + 1)) })));
  }
  if (op === 'top_threat_industries' || op === 'top_industries_country') {
    return statsEnv(['Banking/Finance/Insurance', 'Energy & Utilities', 'Education', 'Agriculture', 'Healthcare', 'Empty', 'Consulting']
      .map((ind, i) => ({ Industry: ind, Threattype: 'virus', Count: Math.round(1e9 / (i + 1)) })));
  }
  if (op === 'get_industry_list') {
    return ['Healthcare', 'Empty', 'Education', 'Aerospace & Defense'];
  }
  if (op === 'fetch_fortiguard_reports') {
    return { results: [
      { Name: 'Newest Outbreak', Subtitle: 'sub new', Slug: 'newest-outbreak', DateReleased: '2026-11-18 00:00:00' },
      { Name: 'Middle Outbreak', Subtitle: 'sub mid', Slug: 'middle-outbreak', DateReleased: '2026-11-10 00:00:00' },
      { Name: 'Older Outbreak', Subtitle: 'sub old', Slug: 'older-outbreak', DateReleased: '2026-11-01 00:00:00' }
    ] };
  }
  if (op === 'get_encyclopedia_lookup') {
    return {
      Name: 'DNS.PTR.Records.Scan', Type: 'ips', ID: 1003,
      Risk: 'Info', RiskID: 1,
      Summary: 'This indicates an attempt<br/>to scan <i>PTR</i> records.&nbsp;Unauthenticated.',
      Analysis: 'Information disclosure.',
      Action: 'Restrict zone transfers.',
      cve_id: 'CVE-2026-0001, CVE-2026-0002',
      kev: [{ id: 1 }],
      max_epss: '0.05',
      os_list: ['Other'], app_list: ['DNS']
    };
  }
  return {};
}

// Stub both integration endpoints. `over` lets a test reroute a call.
async function installRoutes(page, over) {
  over = over || {};
  await page.route(/\/api\/integration\/connectors\//, (route) => {
    if (over.metadata) { return over.metadata(route); }
    return route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ data: [{
        name: 'fortinet-fortiguard-threat-intelligence', version: '4.2.0',
        configuration: [{ config_id: 'c9', default: true }]
      }] })
    });
  });
  await page.route(/\/api\/integration\/execute\//, (route) => {
    let body = {};
    try { body = JSON.parse(route.request().postData() || '{}'); } catch (e) { /* noop */ }
    if (over.execute) { return over.execute(route, body); }
    return route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ status: 'Success', operation: body.operation, data: fixtureData(body.operation, body.params) })
    });
  });
}

test.describe('fortiGuardThreatLandscape -- reworked view', () => {

  test('renders the five activity cards, kill chain, ranked lists and outbreaks', async ({ page }) => {
    await installRoutes(page);
    const w = await mountWidget(page, 'fortiGuardThreatLandscape', {
      config: { title: 'Landscape E2E', time_windows: 7 },
    });

    // Five cards, hero first, abbreviated count, sparkline drawn.
    await expect(page.locator('[data-testid=tlv-card]')).toHaveCount(5);
    await expect(page.locator('[data-testid=tlv-card-count]').first()).toHaveText(/^8\.6B$/);
    await expect(page.locator('.tlv-spark svg').first()).toBeVisible();

    // Seven kill chain phases; the two the feed never fills say so in words.
    await expect(page.locator('[data-testid=tlv-kc-phase]')).toHaveCount(7);
    await expect(page.locator('.tlv-kc-quiet')).toHaveCount(2);
    await expect(page.locator('[data-testid=tlv-kc-metric]').first()).toContainText('ActiveScan');

    // Ten ranked threat rows across the two columns.
    await expect(page.locator('[data-testid=tlv-threat-row]')).toHaveCount(10);

    // Countries resolve ISO2 codes to names; the feed's Empty placeholder
    // never reaches the industry list.
    await expect(page.locator('[data-testid=tlv-country-row]').first()).toContainText('United States');
    await expect(page.locator('[data-testid=tlv-industry-row]')).toHaveCount(5);
    await expect(page.locator('[data-testid=tlv-industry-row]', { hasText: 'Empty' })).toHaveCount(0);

    // Outbreak strip: three latest alerts with FortiGuard links.
    await expect(page.locator('[data-testid=tlv-outbreak-item]')).toHaveCount(3);
    await expect(page.locator('[data-testid=tlv-outbreak-item]').first()).toContainText('Newest Outbreak');

    // Freshness stamp from the feed's Logtime.
    await expect(page.locator('.tlv-asof')).toContainText(LOGTIME);
  });

  test('a threat row opens the encyclopedia drill-down', async ({ page }) => {
    await installRoutes(page);
    const w = await mountWidget(page, 'fortiGuardThreatLandscape', {
      config: { title: 'Landscape E2E', time_windows: 7 },
    });
    await expect(page.locator('[data-testid=tlv-threat-row]').first()).toBeVisible();

    await page.locator('[data-testid=tlv-threat-row]').first().click();
    const drawer = page.locator('[data-testid=tlv-drawer]');
    await expect(drawer).toBeVisible();
    await expect(page.locator('[data-testid=tlv-drawer-title]')).toContainText('DNS.PTR.Records.Scan');
    await expect(page.locator('[data-testid=tlv-drawer-risk]')).toHaveText('info');
    await expect(drawer).toContainText('This indicates an attempt to scan PTR records. Unauthenticated.');
    await expect(drawer).toContainText('CVE-2026-0001');
    await expect(page.locator('[data-testid=tlv-drawer-link]')).toHaveAttribute('href', 'https://www.fortiguard.com/encyclopedia/ips/1000');
  });

  test('clicking a country filters the view and offers the clear button', async ({ page }) => {
    await installRoutes(page);
    const w = await mountWidget(page, 'fortiGuardThreatLandscape', {
      config: { title: 'Landscape E2E', time_windows: 7 },
    });
    await expect(page.locator('[data-testid=tlv-country-row]').first()).toBeVisible();

    await page.locator('[data-testid=tlv-country-row]').first().click();
    // The list IS the filter now: it hides immediately, the industry panel
    // names the filter, and a clear button appears.
    await expect(page.locator('[data-testid=tlv-country-row]')).toHaveCount(0);
    await expect(page.locator('.tlv-panel-hint')).toContainText('United States');
    await expect(page.locator('button.clear-all-filter')).toBeVisible();

    await page.locator('button.clear-all-filter').click();
    await expect(page.locator('[data-testid=tlv-country-row]').first()).toBeVisible();
  });

  test('a missing connector shows one overlay with retry, not eight empty panels', async ({ page }) => {
    await installRoutes(page, {
      metadata: (route) => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ data: [] }) }),
    });
    const w = await mountWidget(page, 'fortiGuardThreatLandscape', {
      config: { title: 'Landscape E2E', time_windows: 7 },
    });

    const overlay = page.locator('[data-testid=tlv-load-error]');
    await expect(overlay).toBeVisible();
    await expect(overlay).toContainText('could not be loaded');
    await expect(page.locator('[data-testid=tlv-card]')).toHaveCount(0);
    await expect(page.locator('[data-testid=tlv-kc-phase]')).toHaveCount(0);

    // The overlay's retry re-runs the wave (still failing here, still overlay).
    await page.locator('.tlv-retry').click();
    await expect(overlay).toBeVisible();
  });

  test('demo mode renders the whole view with zero connector calls', async ({ page }) => {
    const integrationCalls = [];
    await page.route(/\/api\/integration\//, (route) => {
      integrationCalls.push(route.request().url());
      return route.fulfill({ status: 500, contentType: 'application/json', body: '{}' });
    });
    const w = await mountWidget(page, 'fortiGuardThreatLandscape', {
      config: { title: 'Landscape E2E', demoMode: true, demoIntensity: 50 },
    });

    await expect(page.locator('.tlv-demo-chip')).toBeVisible();
    await expect(page.locator('[data-testid=tlv-card]')).toHaveCount(5);
    await expect(page.locator('[data-testid=tlv-card-count]').first()).toHaveText(/B$/);
    await expect(page.locator('[data-testid=tlv-kc-phase]')).toHaveCount(7);
    await expect(page.locator('.tlv-kc-quiet')).toHaveCount(2);
    await expect(page.locator('[data-testid=tlv-threat-row]')).toHaveCount(10);
    await expect(page.locator('[data-testid=tlv-outbreak-item]')).toHaveCount(3);
    // No feed timestamp to claim in demo mode.
    await expect(page.locator('.tlv-asof')).toHaveCount(0);

    // The drill-down skips the encyclopedia and links to the search instead.
    await page.locator('[data-testid=tlv-threat-row]').first().click();
    const drawer = page.locator('[data-testid=tlv-drawer]');
    await expect(drawer).toBeVisible();
    await expect(drawer).toContainText('Demo data');
    await expect(page.locator('[data-testid=tlv-drawer-link]')).toHaveAttribute('href', /fortiguard\.com\/search\?q=/);

    expect(integrationCalls).toEqual([]);
  });
});
