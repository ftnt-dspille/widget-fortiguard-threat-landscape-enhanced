"use strict";
// A widget that renders before its locale file arrives must still end up with real text.
// `{{ ::'ns.KEY' | translate }}` is a one-time binding: it freezes the raw key if the
// translation partial loads after first render, and the analyst sees `ns.KEY` on screen.
// Every translate expression must be a normal (re-evaluating) binding, and the controller
// must not translate synchronously (instantTranslate returns the raw key before load).
//
//   make test-unit WIDGET=<this widget>

const fs = require("fs");
const path = require("path");

const WIDGET = path.join(__dirname, "..", "widget");
const read = (f) => fs.readFileSync(path.join(WIDGET, f), "utf8");

describe("translations survive a late-loading locale file", () => {
  test.each(["view.html", "edit.html"])("%s has no one-time translate bindings", (file) => {
    const html = read(file);
    const frozen = html.match(/\{\{\s*::[^}]*\|\s*translate/g) || [];
    expect(frozen).toEqual([]);
    // and it does use the filter at all, so the test is not vacuous
    expect(html).toMatch(/\|\s*translate/);
  });

  test("the view controller does not translate synchronously", () => {
    expect(read("view.controller.js")).not.toMatch(/instantTranslate\(/);
  });
});

describe("locale files keep key parity", () => {
  const LOCALES = ["en", "fr_fr", "ja", "ko", "zh_cn", "zh_tw"];
  const readLocale = (code) =>
    JSON.parse(fs.readFileSync(path.join(WIDGET, "widgetAssets/locales", code + ".json"), "utf8")).threatLandscapeView;

  test.each(LOCALES.slice(1))("%s has exactly the keys en has, all filled in", (code) => {
    const en = readLocale("en");
    const other = readLocale(code);
    expect(Object.keys(other).sort()).toEqual(Object.keys(en).sort());
    for (const key of Object.keys(en)) {
      expect(typeof other[key]).toBe("string");
      expect(other[key]).not.toBe("");
    }
  });

  test("every key the templates and controller reference exists in en", () => {
    const en = readLocale("en");
    const refs = new Set();
    // Keys start uppercase, so the widget's threatLandscapeView.css path is
    // not mistaken for a translation key.
    const re = /threatLandscapeView\.([A-Z][A-Za-z0-9_]*)/g;
    for (const file of ["view.html", "edit.html", "view.controller.js"]) {
      let m;
      while ((m = re.exec(read(file)))) { refs.add(m[1]); }
    }
    // A trailing underscore is a dynamic prefix (`'threatLandscapeView.PHASE_' + id`):
    // it is complete when some en key starts with it.
    const missing = [...refs].filter((k) =>
      k.endsWith("_") ? !Object.keys(en).some((key) => key.startsWith(k)) : !(k in en));
    expect(missing).toEqual([]);
    expect(refs.size).toBeGreaterThan(20); // the check itself is not vacuous
  });
});
