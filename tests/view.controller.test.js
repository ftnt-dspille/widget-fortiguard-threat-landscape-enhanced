"use strict";
// Unit test for the reworked Threat Landscape view controller. Boots a bare
// `cybersponse` module with the REAL service (mocked transport), loads the
// controller IIFE, and asserts what the analyst gets: ordered cards with
// abbreviated counts and sparklines, the self-drawn kill chain with the feed's
// category breakdown, ranked threats/lists with junk labels filtered, the
// outbreak strip, stale-response protection, failure surfacing and demo mode.
//
//   make test-unit WIDGET=fortiGuardThreatLandscape

global.jasmine = global.jasmine || {};
require("angular");
require("angular-mocks");

angular.module("cybersponse", []); // eslint-disable-line no-undef
require("../widget/widgetAssets/js/threatLandscapeView.service.js");
require("../widget/view.controller.js");

const CTRL_NAME = "fortiGuardThreatLandscape102DevCtrl";
const ngModule = window.angular.mock.module; // eslint-disable-line no-undef
const ngInject = window.angular.mock.inject; // eslint-disable-line no-undef

const LOGTIME = "2026-11-19 00:44";
const BASE_RATES = {
  "Malicious Activity Detected": 8.6e9,
  "Intrusion Prevention Activity": 8.0e9,
  "Malware Distribution Activity": 1.5e8,
  "Botnet Activity Detected": 1.0e7,
  "Endpoint Activity Detected": 1.1e8
};

let toasts;
let runAction; // (connector, version, operation, configId, params) -> promise
let deferredMode; // when true, runAction returns hand-resolvable deferreds
let deferreds;
let moduleRegistered; // angular-mocks refuses a second module() after inject()

function statsEnvelope(type, rows) {
  return { data: [{ Logtime: LOGTIME, Stats: rows }] };
}

// Dispatch a connector call to a live-shaped response (shapes probed from the
// fortinet-fortiguard-threat-intelligence connector's feed operations).
function fixtureFor(operation, params) {
  const win = Number(params.time_windows || 7);
  if (operation.indexOf("threat_activities_statistics") === 0) {
    const base = BASE_RATES[params.threat_type] || 1e6;
    const row = { Count: Math.round(base * win / 7), Threattype: params.threat_type, trend: win === 21 ? null : { percentage: "1.5", direction: "up" } };
    if (params.country) { row.Country = params.country; }
    if (params.industry) { row.Industry = params.industry; }
    return statsEnvelope(params.threat_type, [row]);
  }
  if (operation.indexOf("kill_chain_metrics") === 0) {
    return { data: [
      { id: "reconnaissance", title: "Reconnaissance", metrics: [{ Threattype: "ips", Threat_category: "ActiveScan", Count: 51168776659 }] },
      { id: "weaponization", title: "Weaponization", metrics: [] },
      { id: "delivery", title: "Delivery", metrics: [
        { Threattype: "virus", Threat_category: "DriveByDownload", Count: 3851716 },
        { Threattype: "virus", Threat_category: "MalOfficeDocs", Count: 4042528 },
      ] },
      { id: "exploitation", title: "Exploitation", metrics: [
        { Threattype: "ips", Threat_category: "BruteForce", Count: 935141439 },
        { Threattype: "ips", Threat_category: "Exploitation Attempts", Count: 22426573973 },
      ] },
      { id: "installation", title: "Installation", metrics: [{ Threattype: "virus", Threat_category: "Trojans", Count: 18660493 }] },
      { id: "command-and-control", title: "Command & Control", metrics: [] },
      { id: "actions-on-objectives", title: "Actions on Objectives", metrics: [
        { Threattype: "virus", Threat_category: "Ranswomware", Count: 125717 },
        { Threattype: "ips", Threat_category: "DenialOfService", Count: 1707562948 },
      ] },
    ] };
  }
  if (operation.indexOf("top_threats") === 0) {
    const virus = params.threat_type === "Malware";
    const names = virus
      ? ["W32/BackDoor.Prosiak", "HTML/Phish.Tag", "MSExcel/CVE_2017_0199", "PossibleThreat.RF", "Riskware/CoinMiner"]
      : ["DNS.PTR.Records.Scan", "HTTP.Suspicious.Headers", "SIPVicious.SIP.Scanner", "Modbus.TCP.Unauthorized.Read", "TCP.Out.Of.Range.Timestamp"];
    return { data: [{ Logtime: LOGTIME, Stats: names.map((n, i) => ({
      Name: n, ID: 1000 + i, Threattype: virus ? "virus" : "ips", Count: Math.round(1e9 / (i + 1)),
    })) }] };
  }
  if (operation === "top_threat_countries" || operation === "top_countries_industry") {
    return statsEnvelope("ips", ["US", "VN", "IN", "NZ", "CH", "ID"].map((c, i) => ({
      Country: c, Threattype: "ips", Count: Math.round(1e10 / (i + 1)),
    })));
  }
  if (operation === "top_threat_industries" || operation === "top_industries_country") {
    return statsEnvelope("virus", ["Banking/Finance/Insurance", "Energy & Utilities", "Education", "Agriculture", "Healthcare", "Empty", "Consulting"]
      .map((ind, i) => ({ Industry: ind, Threattype: "virus", Count: Math.round(1e9 / (i + 1)) })));
  }
  if (operation === "get_industry_list") {
    return { data: ["Healthcare", "Empty", "Education", "Aerospace & Defense"] };
  }
  if (operation === "fetch_fortiguard_reports") {
    return { data: { results: [
      { Name: "Older Outbreak", Subtitle: "sub old", Slug: "older-outbreak", Date: "2026-11-01 00:00:00", DateReleased: "2026-11-01 00:00:00" },
      { Name: "Newest Outbreak", Subtitle: "sub new", Slug: "newest-outbreak", Date: "2026-11-18 00:00:00", DateReleased: "2026-11-18 00:00:00" },
      { Name: "Middle Outbreak", Subtitle: "sub mid", Slug: "middle-outbreak", Date: "2026-11-10 00:00:00", DateReleased: "2026-11-10 00:00:00" },
      { Name: "Fourth Outbreak", Subtitle: "sub 4", Slug: "fourth-outbreak", Date: "2026-11-09 00:00:00", DateReleased: "2026-11-09 00:00:00" },
    ] } };
  }
  if (operation === "get_encyclopedia_lookup") {
    return { data: {
      Name: "Modbus.TCP.Unauthorized.Read.Request.PLC", Type: "ips", ID: 11529,
      Risk: "Info", RiskID: 1,
      Summary: "This indicates an attempt<br/>to read <i>PLC</i> data.&nbsp;Unauthenticated.",
      Analysis: "Information Leakage.",
      Action: "Limit network access to PLC devices.",
      cve_id: "CVE-2026-0001, CVE-2026-0002",
      kev: [{ id: 1 }],
      max_epss: "0.05",
      os_list: ["Other"], app_list: ["SCADA"],
    } };
  }
  return { data: {} };
}

const ngQ = () => window.angular.injector(["ng"]).get("$q"); // eslint-disable-line no-undef

function setup(configOver, extra, router) {
  toasts = [];
  runAction = jest.fn();
  deferredMode = false;
  deferreds = [];
  const register = ($provide) => {
    $provide.value("API", { INTEGRATIONS: "/api/integration/" });
    $provide.value("toaster", { error: (t) => toasts.push(t.body) });
    $provide.value("widgetBasePath", "/w/");
    $provide.value("config", Object.assign({ time_windows: 7 }, configOver || {}));
    $provide.value("$rootScope", Object.assign(window.angular.injector(["ng"]).get("$rootScope"), { theme: { id: "dark" } }));
    // Native promises settle on real ticks, which the flush helper interleaves
    // with digests -- no $q needed for the transport mocks.
    $provide.value("$resource", () => ({
      get: () => ({ $promise: Promise.resolve({ data: [{
        name: "fortinet-fortiguard-threat-intelligence", version: "4.2.0",
        configuration: [{ config_id: "c9", default: true }],
      }] }) }),
    }));
    $provide.value("connectorService", {
      executeConnectorAction: (...a) => {
        if (deferredMode) {
          const d = ngQ().defer();
          deferreds.push({ d, args: a });
          return d.promise;
        }
        return runAction(...a);
      },
    });
    if (extra) { extra($provide); }
  };
  // angular-mocks refuses a second module() once an injector exists: a test
  // that boots two scopes (demo determinism) reuses the first registration.
  if (!moduleRegistered) {
    ngModule("cybersponse", register);
    moduleRegistered = true;
  }
  runAction.mockImplementation((name, version, operation, configId, params) =>
    Promise.resolve((router || fixtureFor)(operation, params || {})));
}

// $q chains only advance on a digest; alternate real ticks with digests.
async function flush(scope, rounds) {
  for (let i = 0; i < (rounds || 6); i++) {
    await new Promise((r) => setTimeout(r, 0));
    scope.$root.$digest();
  }
}

async function boot(configOver, extra, router) {
  setup(configOver, extra, router);
  let scope;
  let $httpBackend;
  ngInject(["$controller", "$rootScope", "$httpBackend", ($controller, $rs, $hb) => {
    $httpBackend = $hb;
    $httpBackend.whenGET(/widgetAssets\/lib\/iso2_countries\.json/).respond(200, {
      US: { name: "United States", filter: "United States" },
      VN: { name: "Vietnam", filter: "Vietnam" },
      IN: { name: "India", filter: "India" },
    });
    $httpBackend.whenGET(/widgetAssets\/json\/countries\.json/).respond(200, { countries: ["United States", "India"] });
    scope = $rs.$new();
    $controller(CTRL_NAME, { $scope: scope });
  }]);
  const safeFlushHttp = () => { try { $httpBackend.flush(); } catch (e) { /* none pending */ } };
  safeFlushHttp();
  await flush(scope);
  safeFlushHttp();
  await flush(scope);
  return scope;
}

beforeEach(() => {
  moduleRegistered = false;
  jest.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => jest.restoreAllMocks());

/* ---------------------------------------------------------------- cards */

describe("summary cards", () => {
  test("five categories load in order with the hero first and abbreviated counts", async () => {
    const scope = await boot();
    expect(scope.cards.map((c) => c.key)).toEqual(["malicious", "ips", "malware", "botnet", "endpoint"]);
    expect(scope.cards[0].loading).toBe(false);
    expect(scope.cards[0].data.count).toBeGreaterThan(0);
    expect(scope.abbreviate(scope.cards[0].data.count)).toMatch(/B$/);
    expect(scope.cards[4].key).toBe("endpoint"); // the category the original dropped
    expect(scope.cards[1].data.trend.direction).toBe("up");
  });

  test("sparklines read oldest to newest as daily rates", async () => {
    const scope = await boot();
    const spark = scope.cards[0].data.spark;
    expect(spark).toBeTruthy();
    expect(spark.line.split(" ")).toHaveLength(5);
    // the fixture scales counts with the window, so daily rates are flat:
    // the line starts at x=0 (21d) and ends at the right edge (1d).
    const first = spark.line.split(" ")[0].split(",").map(Number);
    expect(first[0]).toBe(0);
    expect(Number(spark.last[0])).toBeGreaterThan(0);
  });

  test("an unsupported configured window is clamped to one the feed answers", async () => {
    const scope = await boot({ time_windows: 30 });
    expect(scope.filters.dateRange).toBe(7);
  });
});

/* ------------------------------------------------------------ kill chain */

describe("kill chain", () => {
  test("phases carry the feed's category breakdown, scaled within the phase", async () => {
    const scope = await boot();
    const exploitation = scope.killChainSections.find((s) => s.id === "exploitation");
    expect(exploitation.metrics.map((m) => m.label)).toEqual(["Exploitation Attempts", "BruteForce"]);
    expect(exploitation.metrics[0].pct).toBe(100);
    expect(exploitation.totalCount).toBe(935141439 + 22426573973);
    // phase progress is relative to the biggest phase (reconnaissance)
    const recon = scope.killChainSections.find((s) => s.id === "reconnaissance");
    expect(recon.progressPercent).toBe(100);
    expect(exploitation.progressPercent).toBeLessThan(100);
  });

  test("phases the feed never fills render as quiet, not blank", async () => {
    const scope = await boot();
    const weaponization = scope.killChainSections.find((s) => s.id === "weaponization");
    expect(weaponization.metrics).toEqual([]);
    expect(weaponization.totalCount).toBe(0);
  });
});

/* ---------------------------------------------------- threats and lists */

describe("ranked sections", () => {
  test("top exploits and malware are ranked, five each, and open a drill", async () => {
    const scope = await boot();
    expect(scope.topThreats.exploit.items.map((i) => i.title)[0]).toBe("DNS.PTR.Records.Scan");
    expect(scope.topThreats.malware.items).toHaveLength(5);
    expect(scope.topThreats.exploit.items[0].rank).toBe(1);

    scope.openThreat(scope.topThreats.exploit.items[3], scope.topThreats.exploit);
    expect(scope.drill.item.id).toBe(1003);
    await flush(scope);
    expect(scope.drill.loading).toBe(false); // the drawer must leave its spinner
    expect(scope.drill.lookup.risk).toBe("info");
    expect(scope.drill.lookup.summary).toBe("This indicates an attempt to read PLC data. Unauthenticated.");
    expect(scope.drill.lookup.cves).toEqual(["CVE-2026-0001", "CVE-2026-0002"]);
    expect(scope.drill.lookup.kev).toBe(1);
    expect(scope.drill.url).toBe("https://www.fortiguard.com/encyclopedia/ips/1003");
  });

  test("junk industry labels (the feed's Empty placeholder) never reach a list", async () => {
    const scope = await boot();
    expect(scope.topIndustries.items.map((i) => i.title)).not.toContain("Empty");
    expect(scope.industryOptions).not.toContain("Empty");
    expect(scope.topCountries.items[0].title).toBe("United States"); // ISO2 resolved to a name
  });

  test("picking a country from the list filters by the feed's country name", async () => {
    const scope = await boot();
    scope.pickCountry(scope.topCountries.items[0]); // US
    expect(scope.filters.country).toBe("United States");
    expect(scope.showClearFilter).toBe(true);
    expect(scope.topCountries.hidden).toBe(true); // the list IS the filter now
  });

  test("the outbreak strip shows the three latest alerts, newest first", async () => {
    const scope = await boot();
    expect(scope.outbreaks.items.map((o) => o.name)).toEqual(["Newest Outbreak", "Middle Outbreak", "Fourth Outbreak"]);
    expect(scope.outbreaks.items[0].url).toBe("https://www.fortiguard.com/outbreak-alert/newest-outbreak");
  });
});

/* --------------------------------------------------- stale responses */

describe("stale-response protection", () => {
  test("a slow answer from an older filter wave never overwrites a newer one", async () => {
    const scope = await boot();
    deferredMode = true;

    scope.filters.dateRange = 7;
    scope.applyFilters();
    await flush(scope, 3);
    expect(deferreds.length).toBeGreaterThan(0);
    const waveOne = deferreds.splice(0);

    scope.filters.dateRange = 3;
    scope.applyFilters();
    await flush(scope, 3);
    const waveTwo = deferreds.splice(0);

    // Wave two resolves first with its own numbers, then wave one lands late.
    const killChainOp = (x) => x.args[2].indexOf("kill_chain_metrics") === 0;
    waveTwo.filter(killChainOp).forEach((x) => x.d.resolve({ data: [{ id: "exploitation", metrics: [{ Threattype: "ips", Threat_category: "NewerWave", Count: 222 }] }] }));
    await flush(scope, 3);
    waveOne.filter(killChainOp).forEach((x) => x.d.resolve({ data: [{ id: "exploitation", metrics: [{ Threattype: "ips", Threat_category: "StaleWave", Count: 111 }] }] }));
    await flush(scope, 3);

    const exploitation = scope.killChainSections.find((s) => s.id === "exploitation");
    expect(exploitation.metrics[0].label).toBe("NewerWave");
    expect(scope.filters.dateRange).toBe(3);
    expect(scope.dateRange).toBe(3);
  });
});

/* ---------------------------------------------------- failure handling */

describe("failure handling", () => {
  test("a missing connector fails once at setup and shows the overlay, not eight failing sections", async () => {
    const scope = await boot({}, ($provide) => {
      // the connector lookup returns nothing: meta() rejects for every wave
      $provide.value("$resource", () => ({ get: () => ({ $promise: Promise.resolve({ data: [] }) }) }));
      $provide.value("connectorService", { executeConnectorAction: () => Promise.reject(new Error("unreachable")) });
    });
    expect(scope.loadError).toMatch(/not installed/);
    expect(toasts).toHaveLength(1); // one toast for the whole wave, not one per section
    expect(runAction).not.toHaveBeenCalled();
  });

  test("one failing section shows its own error and leaves the rest up", async () => {
    const scope = await boot({}, null, (operation, params) => {
      if (operation.indexOf("kill_chain_metrics") === 0) {
        return Promise.reject({ data: { message: "upstream timeout" } });
      }
      return fixtureFor(operation, params || {});
    });
    expect(scope.killChain.error).toBe("upstream timeout");
    expect(scope.loadError).toBeNull();
    expect(scope.cards[0].error).toBeNull();
    expect(scope.topThreats.exploit.items.length).toBe(5);
  });
});

/* ---------------------------------------------------------- demo mode */

describe("demo mode", () => {
  test("renders everything with no connector traffic, deterministically", async () => {
    const scopeA = await boot({ demoMode: true, demoIntensity: 50 });
    expect(scopeA.cards.map((c) => c.data.count)).not.toContain(undefined);
    expect(scopeA.cards[0].data.spark).toBeTruthy();
    expect(scopeA.killChainSections.find((s) => s.id === "exploitation").metrics.length).toBe(2);
    expect(scopeA.topThreats.malware.items).toHaveLength(5);
    expect(scopeA.outbreaks.items).toHaveLength(3);
    expect(scopeA.asOf).toBeNull(); // no feed timestamp to claim

    const scopeB = await boot({ demoMode: true, demoIntensity: 50 });
    expect(scopeB.cards.map((c) => c.data.count)).toEqual(scopeA.cards.map((c) => c.data.count));

    // filters re-seed the view instead of hitting the connector
    scopeA.filters.dateRange = 3;
    scopeA.applyFilters();
    expect(scopeA.filters.dateRange).toBe(3);
    expect(scopeA.cards[0].data.count).not.toBe(scopeB.cards[0].data.count);
  });

  test("the drill-down in demo mode skips the encyclopedia and links to the search", async () => {
    const scope = await boot({ demoMode: true });
    scope.openThreat(scope.topThreats.exploit.items[0], scope.topThreats.exploit);
    expect(scope.drill.demo).toBe(true);
    expect(scope.drill.loading).toBe(false);
    expect(scope.drill.url).toContain("fortiguard.com/search?q=");
  });
});
