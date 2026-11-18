"use strict";
// Failure handling for the Landscape connector calls: a missing connector, a
// connector with no default configuration and a failed request must each reach
// the analyst as a toast (and a readable error), never only the console.
//
//   make test-unit WIDGET=fortiGuardThreatLandscape

global.jasmine = global.jasmine || {};
require("angular");
require("angular-mocks");

angular.module("cybersponse", []); // eslint-disable-line no-undef
require("../widget/widgetAssets/js/threatLandscapeView.service.js");

const ngModule = window.angular.mock.module; // eslint-disable-line no-undef
const ngInject = window.angular.mock.inject; // eslint-disable-line no-undef

let lookup;
let toasts;
let runAction;

beforeEach(() => {
  jest.spyOn(console, "error").mockImplementation(() => {});
  toasts = [];
  runAction = jest.fn();
  ngModule("cybersponse", ($provide) => {
    $provide.value("API", { INTEGRATIONS: "/api/integration/" });
    $provide.value("toaster", { error: (t) => toasts.push(t.body) });
    $provide.value("connectorService", { executeConnectorAction: (...a) => runAction(...a) });
    $provide.value("$resource", () => ({ get: () => ({ $promise: lookup() }) }));
  });
});
afterEach(() => jest.restoreAllMocks());

function run(setLookup, cb) {
  ngInject(["threatLandscapeViewService", "$rootScope", "$q", (svc, $rs, $q) => {
    lookup = () => setLookup($q);
    let err = null;
    svc.executeAction("fortinet-fortiguard-threat-intelligence", "act", { a: 1 }).catch((e) => { err = e; });
    $rs.$digest();
    cb(err);
  }]);
}

test("connector not installed -> readable error and one toast, no TypeError", () => {
  run(($q) => $q.resolve({ data: [] }), (err) => {
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(TypeError);
    expect(err.message).toMatch(/not installed/);
    expect(toasts).toHaveLength(1);
    expect(runAction).not.toHaveBeenCalled();
  });
});

test("no default configuration -> readable error and one toast", () => {
  run(($q) => $q.resolve({ data: [{ version: "4.2.0", configuration: [{ config_id: "c1", default: false }] }] }), (err) => {
    expect(err).not.toBeInstanceOf(TypeError);
    expect(err.message).toMatch(/no default configuration/);
    expect(toasts).toHaveLength(1);
  });
});

test("default configuration -> runs the action with its id and does not toast", () => {
  run(($q) => {
    runAction.mockReturnValue($q.resolve({ data: [] }));
    return $q.resolve({ data: [{ version: "4.2.0", configuration: [{ config_id: "c7", default: true }] }] });
  }, (err) => {
    expect(err).toBeNull();
    expect(runAction).toHaveBeenCalledWith("fortinet-fortiguard-threat-intelligence", "4.2.0", "act", "c7", { a: 1 });
    expect(toasts).toHaveLength(0);
  });
});

test("request failure -> toasted once with the platform's reason", () => {
  run(($q) => $q.reject({ data: { message: "timeout" } }), (err) => {
    expect(err).toBeTruthy();
    expect(toasts).toHaveLength(1);
    expect(toasts[0]).toMatch(/request failed: timeout/);
  });
});
