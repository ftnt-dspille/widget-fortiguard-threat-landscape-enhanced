/* Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end */
'use strict';

/*
 * FortiGuard Threat Landscape - reworked to make the feed's numbers nameable
 * and comparable:
 *   - five activity categories (the feed also answers Endpoint Activity, the
 *     original widget dropped it), each with an abbreviated count, the feed's
 *     own trend and a per-day sparkline across the five windows;
 *   - the kill chain drawn by this widget (no killchainphases dependency),
 *     with the feed's per-category breakdown (BruteForce, Ransomware, ...);
 *   - top exploits and malware with an encyclopedia drill-down (risk,
 *     analysis, recommended action, CVEs);
 *   - top targeted countries and industries, click-to-filter;
 *   - the latest FortiGuard outbreak alerts and a feed freshness stamp.
 * Every failure reaches the widget (overlay or per-section message), never
 * only the console, and a demo mode renders the whole view without a
 * connector.
 */
(function () {
  angular
    .module('cybersponse')
    .controller('fortiGuardThreatLandscape103DevCtrl', fortiGuardThreatLandscape103DevCtrl);

  fortiGuardThreatLandscape103DevCtrl.$inject = ['$scope', '$rootScope', '$http', '$q', 'threatLandscapeViewService', 'config', 'widgetBasePath'];

  function fortiGuardThreatLandscape103DevCtrl($scope, $rootScope, $http, $q, threatLandscapeViewService, config, widgetBasePath) {

    /* ================= CONSTANTS ================= */

    // The only windows the feed answers; totals do not scale with the window,
    // so comparisons use daily rates, never raw sums.
    var WINDOWS = [1, 3, 7, 14, 21];
    // Placeholder labels the feed uses for "no industry recorded".
    var JUNK_LABELS = /^(empty|none|unknown|n\/a|-|)$/i;
    var ENCYCLOPEDIA_SOURCE = { ips: 'Intrusion Prevention', virus: 'Viruses', botnet: 'Botnet' };

    /* ================= BASE CONFIG ================= */

    $scope.theme = $rootScope.theme.id;
    $scope.config = config;
    $scope.widgetBasePath = widgetBasePath;
    $scope.widgetCSS = widgetBasePath + 'widgetAssets/css/threatLandscapeView.css';

    $scope.showClearFilter = false;
    $scope.clearFilters = clearFilters;
    $scope.applyFilters = applyFilters;
    $scope.pickCountry = pickCountry;
    $scope.openThreat = openThreat;
    $scope.closeThreat = function () { $scope.drill = null; };
    $scope.retry = retry;
    $scope.abbreviate = abbreviate;

    // Message shown in the widget when the connector itself is unusable
    // (never console only). Section-level failures show in their panels.
    $scope.loadError = null;
    // Feed freshness ("2026-11-19 00:44"), the newest Logtime we saw.
    $scope.asOf = null;

    $scope.demoMode = !!(config && config.demoMode);
    $scope.demoIntensity = demoIntensity();

    /* ================= FILTERS ================= */

    // An array, not an object: ng-repeat and ng-options sort object keys
    // alphabetically, which would order the dropdown 1, 14, 21, 3, 7.
    $scope.dateRanges = [
      { label: 'Last 1 Day', value: 1 },
      { label: 'Last 3 Days', value: 3 },
      { label: 'Last 7 Days', value: 7 },
      { label: 'Last 14 Days', value: 14 },
      { label: 'Last 21 Days', value: 21 }
    ];
    $scope.filters = {
      dateRange: _window(config.time_windows || 7),
      industry: null,
      country: null
    };
    $scope.dateRange = $scope.filters.dateRange;

    function _window(n) {
      n = parseInt(n, 10);
      return WINDOWS.indexOf(n) >= 0 ? n : 7;
    }

    function demoIntensity() {
      var n = parseInt(config && config.demoIntensity, 10);
      if (!n || isNaN(n)) { n = 50; }
      return Math.max(10, Math.min(200, n));
    }

    /* ================= SUMMARY CARDS ================= */

    // An array, not an object: ng-repeat sorts object keys alphabetically,
    // which would make a detail card the hero.
    $scope.cards = [
      createCard('malicious', 'threatLandscapeView.TITLE_IPS_MALICIOUS', 'threatLandscapeView.TOOLTIP_IPS_MALICIOUS', 'Malicious Activity Detected'),
      createCard('ips', 'threatLandscapeView.TITLE_IPS_INTRUSION', 'threatLandscapeView.TOOLTIP_IPS_INTRUSION', 'Intrusion Prevention Activity', 'IPS'),
      createCard('malware', 'threatLandscapeView.TITLE_AV_MALWARE', 'threatLandscapeView.TOOLTIP_AV_MALWARE', 'Malware Distribution Activity', 'AV'),
      createCard('botnet', 'threatLandscapeView.TITLE_C2_BOTNET', 'threatLandscapeView.TOOLTIP_C2_BOTNET', 'Botnet Activity Detected', 'C2'),
      createCard('endpoint', 'threatLandscapeView.TITLE_ENDPOINT', 'threatLandscapeView.TOOLTIP_ENDPOINT', 'Endpoint Activity Detected')
    ];

    function createCard(key, title, tooltip, type, icon) {
      return { key: key, title: title, tooltip: tooltip, type: type, icon: icon, loading: true, error: null, data: null };
    }

    // One request per (type, window, filter) for the page's life: filter
    // changes re-use them, the feed updates far slower than anyone filters.
    var statsCache = {};

    function statsFor(type, window) {
      var key = [type, window, $scope.filters.country || '', $scope.filters.industry || ''].join('|');
      if (!statsCache[key]) {
        var params = { threat_type: type, time_windows: String(window) };
        if ($scope.filters.country) { params.country = $scope.filters.country; }
        if ($scope.filters.industry) { params.industry = $scope.filters.industry; }
        statsCache[key] = threatLandscapeViewService.execute(statsAction(), params).then(function (res) {
          noteAsOf(res);
          var row = threatLandscapeViewService.stats(res)[0] || {};
          return { count: Number(row.Count) || 0, trend: row.trend || null };
        }).catch(function () { delete statsCache[key]; return null; });
      }
      return statsCache[key];
    }

    function statsAction() {
      if ($scope.filters.country && $scope.filters.industry) {
        return 'threat_activities_statistics_by_country_and_industry';
      }
      if ($scope.filters.country) {
        return 'threat_activities_statistics_by_country';
      }
      if ($scope.filters.industry) {
        return 'threat_activities_statistics_by_industry';
      }
      return 'threat_activities_statistics';
    }

    function loadCards(seq) {
      $scope.cards.forEach(function (card) {
        card.loading = true;
        card.error = null;
        statsFor(card.type, $scope.filters.dateRange).then(function (row) {
          if (!guard(seq)) { return; }
          if (row) {
            card.data = {
              count: row.count,
              trend: row.trend,
              perDay: row.count / $scope.filters.dateRange,
              spark: card.data && card.data.spark
            };
          } else {
            card.error = 'unavailable';
          }
        }).finally(function () {
          if (guard(seq)) { card.loading = false; }
        });
      });
      // The other sparkline windows fill in behind the headline numbers so
      // the first paint stays fast.
      $scope.cards.forEach(function (card) {
        $q.all(WINDOWS.map(function (w) { return statsFor(card.type, w); })).then(function (rows) {
          if (!guard(seq)) { return; }
          var byWindow = {};
          WINDOWS.forEach(function (w, i) { byWindow[w] = rows[i] ? rows[i].count : null; });
          var sparkLine = spark(byWindow, true);
          if (sparkLine && card.data) { card.data.spark = sparkLine; }
        });
      });
    }

    /* ================= KILL CHAIN ================= */

    $scope.killChainSections = [
      { id: 'reconnaissance', metrics: [], totalCount: 0, progressPercent: 0 },
      { id: 'weaponization', metrics: [], totalCount: 0, progressPercent: 0 },
      { id: 'delivery', metrics: [], totalCount: 0, progressPercent: 0 },
      { id: 'exploitation', metrics: [], totalCount: 0, progressPercent: 0 },
      { id: 'installation', metrics: [], totalCount: 0, progressPercent: 0 },
      { id: 'command-and-control', metrics: [], totalCount: 0, progressPercent: 0 },
      { id: 'actions-on-objectives', metrics: [], totalCount: 0, progressPercent: 0 }
    ];
    $scope.killChain = { loading: true, error: null };

    function killChainAction() {
      if ($scope.filters.country && $scope.filters.industry) {
        return 'kill_chain_metrics_country_industry';
      }
      if ($scope.filters.country) {
        return 'kill_chain_metrics_country';
      }
      if ($scope.filters.industry) {
        return 'kill_chain_metrics_industry';
      }
      return 'kill_chain_metrics';
    }

    function loadKillChain(seq) {
      $scope.killChain.loading = true;
      $scope.killChain.error = null;
      threatLandscapeViewService.execute(killChainAction(), { time_windows: String($scope.filters.dateRange) }).then(function (res) {
        if (!guard(seq)) { return; }
        noteAsOf(res);
        applyKillChain(res.data || []);
      }).catch(function (err) {
        console.error('[fortiGuardThreatLandscape] kill chain:', err);
        if (!guard(seq)) { return; }
        $scope.killChain.error = reasonOf(err) || 'unavailable';
      }).finally(function () {
        if (guard(seq)) { $scope.killChain.loading = false; }
      });
    }

    function applyKillChain(apiResponseData) {
      var maxPhase = 0;
      $scope.killChainSections.forEach(function (section) {
        var matched = apiResponseData.filter(function (item) { return item && item.id === section.id; })[0] || {};
        section.metrics = (matched.metrics || []).map(function (m) {
          return { label: m.Threat_category || m.Threattype, type: m.Threattype, count: Number(m.Count) || 0, pct: 0 };
        }).sort(function (a, b) { return b.count - a.count; });
        section.totalCount = section.metrics.reduce(function (sum, m) { return sum + m.count; }, 0);
        maxPhase = Math.max(maxPhase, section.totalCount);
        var phaseMax = section.metrics.reduce(function (m, x) { return Math.max(m, x.count); }, 0) || 1;
        section.metrics.forEach(function (m) { m.pct = Math.max(2, Math.round((m.count / phaseMax) * 100)); });
      });
      $scope.killChainSections.forEach(function (section) {
        section.progressPercent = maxPhase ? (section.totalCount / maxPhase) * 100 : 0;
      });
    }

    /* ================= TOP THREATS ================= */

    $scope.topThreats = {
      exploit: { kind: 'exploit', title: 'threatLandscapeView.TOP_EXPLOITS', type: 'Vulnerability', loading: true, error: null, items: [] },
      malware: { kind: 'malware', title: 'threatLandscapeView.TOP_MALWARE', type: 'Malware', loading: true, error: null, items: [] }
    };

    function topThreatsAction() {
      if ($scope.filters.country && $scope.filters.industry) {
        return 'top_threats_country_industry';
      }
      if ($scope.filters.country) {
        return 'top_threats_by_country';
      }
      if ($scope.filters.industry) {
        return 'top_threats_by_industry';
      }
      return 'top_threats';
    }

    function loadTopThreats(seq, col) {
      col.loading = true;
      col.error = null;
      var params = {
        threat_type: col.type,
        order: 'Descending',
        time_windows: String($scope.filters.dateRange),
        max_records: 5
      };
      if ($scope.filters.country) { params.country = $scope.filters.country; }
      if ($scope.filters.industry) { params.industry = $scope.filters.industry; }
      threatLandscapeViewService.execute(topThreatsAction(), params).then(function (res) {
        if (!guard(seq)) { return; }
        noteAsOf(res);
        col.items = toRanked(threatLandscapeViewService.stats(res), 'Name', 5);
      }).catch(function (err) {
        console.error('[fortiGuardThreatLandscape] top threats:', err);
        if (!guard(seq)) { return; }
        col.items = [];
        col.error = reasonOf(err) || 'unavailable';
      }).finally(function () {
        if (guard(seq)) { col.loading = false; }
      });
    }

    /* ================= COUNTRY AND INDUSTRY LISTS ================= */

    $scope.topCountries = { loading: true, error: null, items: [], hidden: false };
    $scope.topIndustries = { loading: true, error: null, items: [], hidden: false };
    $scope.countries = null;

    // When a filter IS the dimension itself the list has nothing new to say:
    // it hides, and the other list switches to the cross action.
    function loadCountryList(seq) {
      $scope.topCountries.hidden = !!$scope.filters.country;
      if ($scope.topCountries.hidden) { return; }
      loadRankedList(seq, $scope.topCountries, $scope.filters.industry ? 'top_countries_industry' : 'top_threat_countries', 'Country');
    }

    function loadIndustryList(seq) {
      $scope.topIndustries.hidden = !!$scope.filters.industry;
      if ($scope.topIndustries.hidden) { return; }
      loadRankedList(seq, $scope.topIndustries, $scope.filters.country ? 'top_industries_country' : 'top_threat_industries', 'Industry');
    }

    function loadRankedList(seq, target, action, labelKey) {
      target.loading = true;
      target.error = null;
      $q.all(['Vulnerability', 'Malware'].map(function (type) {
        var params = { threat_type: type, order: 'Descending', time_windows: String($scope.filters.dateRange), max_records: 10 };
        if ($scope.filters.country) { params.country = $scope.filters.country; }
        if ($scope.filters.industry) { params.industry = $scope.filters.industry; }
        return threatLandscapeViewService.execute(action, params).then(function (res) {
          noteAsOf(res);
          return threatLandscapeViewService.stats(res);
        }).catch(function (err) {
          console.error('[fortiGuardThreatLandscape] ' + action + ':', err);
          return null;
        });
      })).then(function (groups) {
        if (!guard(seq)) { return; }
        var merged = {};
        groups.forEach(function (rows) {
          (rows || []).forEach(function (s) {
            var label = s[labelKey];
            if (labelKey === 'Industry' && JUNK_LABELS.test(String(label || ''))) { return; }
            if (!label) { return; }
            merged[label] = (merged[label] || 0) + (Number(s.Count) || 0);
          });
        });
        target.items = ranked(Object.keys(merged).map(function (label) {
          return {
            code: labelKey === 'Country' ? label : null,
            title: labelKey === 'Country' ? countryName(label) : label,
            value: merged[label]
          };
        }), 5);
        if (groups.every(function (g) { return g === null; })) {
          target.error = 'unavailable';
        }
      }).finally(function () {
        if (guard(seq)) { target.loading = false; }
      });
    }

    function countryName(code) {
      if ($scope.countries && $scope.countries[code]) { return $scope.countries[code].name; }
      return code || '-';
    }

    function pickCountry(item) {
      var code = item && item.code;
      var mapped = code && $scope.countries && $scope.countries[code];
      $scope.filters.country = (mapped && mapped.filter) || (item && item.title) || null;
      applyFilters();
    }

    /* ================= OUTBREAK ALERTS ================= */

    $scope.outbreaks = { loading: true, error: null, items: [] };

    // Global context, not filter dependent: loaded once per page.
    function loadOutbreaks() {
      $scope.outbreaks.loading = true;
      $scope.outbreaks.error = null;
      threatLandscapeViewService.execute('fetch_fortiguard_reports', { type: ['Outbreak Alert'], limit: 10 }).then(function (res) {
        var rows = (res && res.data && res.data.results) || [];
        $scope.outbreaks.items = rows.slice().sort(function (a, b) {
          return String(b.DateReleased || b.Date || '').localeCompare(String(a.DateReleased || a.Date || ''));
        }).slice(0, 3).map(function (r) {
          return {
            name: r.Name,
            subtitle: r.Subtitle || '',
            date: String(r.DateReleased || r.Date || '').split(' ')[0],
            url: r.Slug ? 'https://www.fortiguard.com/outbreak-alert/' + r.Slug : null
          };
        });
      }).catch(function (err) {
        console.error('[fortiGuardThreatLandscape] outbreaks:', err);
        $scope.outbreaks.error = reasonOf(err) || 'unavailable';
      }).finally(function () {
        $scope.outbreaks.loading = false;
      });
    }

    /* ================= ENCYCLOPEDIA DRILL-DOWN ================= */

    var threatCache = {};

    function encyclopediaFor(item) {
      var key = item.type + '|' + item.id;
      if (!threatCache[key]) {
        threatCache[key] = threatLandscapeViewService.execute('get_encyclopedia_lookup', {
          source: ENCYCLOPEDIA_SOURCE[item.type] || 'Intrusion Prevention',
          id: String(item.id)
        }).then(function (res) {
          return (res && res.data) || null;
        }).catch(function () { delete threatCache[key]; return null; });
      }
      return threatCache[key];
    }

    function openThreat(item, col) {
      var d = $scope.drill = {
        item: item,
        colTitle: col && col.title,
        category: item.type === 'ips' ? 'threatLandscapeView.DRILL_CATEGORY_IPS' : (item.type === 'virus' ? 'threatLandscapeView.DRILL_CATEGORY_AV' : 'threatLandscapeView.DRILL_CATEGORY_SIG'),
        window: $scope.filters.dateRange,
        scope: [$scope.filters.country, $scope.filters.industry].filter(Boolean).join(' / ') || 'worldwide',
        url: encyclopediaUrl(item),
        loading: !$scope.demoMode,
        demo: $scope.demoMode,
        error: null,
        lookup: null
      };
      if ($scope.demoMode) { return; }
      encyclopediaFor(item).then(function (lookup) {
        if ($scope.drill !== d) { return; }
        d.loading = false;
        if (!lookup) { d.error = 'threatLandscapeView.DRILL_LOAD_FAILED'; return; }
        d.lookup = {
          name: lookup.Name || item.title,
          risk: String(lookup.Risk || '').toLowerCase() || riskFromId(lookup.RiskID),
          summary: plainText(lookup.Summary),
          analysis: plainText(lookup.Analysis),
          action: plainText(lookup.Action),
          cves: asList(lookup.cve_id),
          kev: (lookup.kev || []).length,
          epss: lookup.max_epss || '',
          platforms: asList(lookup.os_list).concat(asList(lookup.app_list)).slice(0, 8)
        };
      });
    }

    function encyclopediaUrl(item) {
      var kind = { virus: 'virus', ips: 'ips', botnet: 'botnet' }[String(item.type || '').toLowerCase()];
      // Demo ids are invented; the encyclopedia search still resolves a real name.
      if ($scope.demoMode || !kind || !item.id) {
        return 'https://www.fortiguard.com/search?q=' + encodeURIComponent(item.title) + '&engine=1';
      }
      return 'https://www.fortiguard.com/encyclopedia/' + kind + '/' + item.id;
    }

    function riskFromId(id) {
      return { 1: 'info', 2: 'low', 3: 'medium', 4: 'high', 5: 'critical' }[Number(id)] || '';
    }

    function plainText(html) {
      return String(html || '')
        .replace(/<br\s*\/?>/gi, ' ')
        .replace(/<[^>]+>/g, '')
        .replace(/&nbsp;/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/\s+/g, ' ')
        .trim();
    }

    function asList(value) {
      if (!value) { return []; }
      if (Array.isArray(value)) { return value.filter(Boolean); }
      return String(value).split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    }

    /* ================= SHARED HELPERS ================= */

    function noteAsOf(res) {
      var t = threatLandscapeViewService.logtime(res);
      if (t && (!$scope.asOf || t > $scope.asOf)) { $scope.asOf = t; }
    }

    function reasonOf(err) {
      return err && (err.message || (err.data && (err.data.message || err.data.error)));
    }

    function ranked(entries, want) {
      var sorted = entries.sort(function (a, b) { return b.value - a.value; }).slice(0, want);
      var max = sorted.length ? sorted[0].value : 1;
      sorted.forEach(function (item, i) {
        item.rank = i + 1;
        item.pct = Math.round((item.value / max) * 100);
      });
      return sorted;
    }

    function toRanked(rows, labelKey, want) {
      var usable = rows.filter(function (s) { return s[labelKey]; });
      return ranked(usable.map(function (s) {
        return {
          title: s[labelKey],
          id: s.ID,
          type: s.Threattype,
          value: Number(s.Count) || 0
        };
      }), want);
    }

    function abbreviate(n) {
      if (n === null || n === undefined || isNaN(n)) { return '-'; }
      var a = Math.abs(n);
      if (a >= 1e12) { return (n / 1e12).toFixed(1) + 'T'; }
      if (a >= 1e9) { return (n / 1e9).toFixed(1) + 'B'; }
      if (a >= 1e6) { return (n / 1e6).toFixed(1) + 'M'; }
      if (a >= 1e3) { return (n / 1e3).toFixed(1) + 'K'; }
      return String(Math.round(n));
    }

    // Sparkline over the windows, longest first, so the line reads old -> recent.
    function spark(byWindow, perDay) {
      var wins = WINDOWS.slice().reverse();
      var vals = wins.map(function (w) {
        var v = byWindow[w];
        return v === null || v === undefined ? null : (perDay ? v / w : v);
      });
      var known = vals.filter(function (v) { return v !== null; });
      if (known.length < 2) { return null; }
      var lo = Math.min.apply(null, known);
      var hi = Math.max.apply(null, known);
      var W = 110;
      var H = 30;
      var pts = [];
      vals.forEach(function (v, i) {
        if (v === null) { return; }
        var x = (i / (vals.length - 1)) * W;
        var y = hi === lo ? H / 2 : H - 3 - ((v - lo) / (hi - lo)) * (H - 6);
        pts.push(x.toFixed(1) + ',' + y.toFixed(1));
      });
      return {
        line: pts.join(' '),
        area: '0,' + H + ' ' + pts.join(' ') + ' ' + W + ',' + H,
        last: pts[pts.length - 1].split(',')
      };
    }

    /* ================= LOADING WAVES ================= */

    // Every applyFilters bumps the wave counter; an async response from an
    // older wave never writes the scope, so rapid Apply clicks cannot let a
    // stale answer overwrite a newer filter's results.
    var waveSeq = 0;

    function guard(seq) { return seq === waveSeq; }

    function refreshAll() {
      var seq = ++waveSeq;
      $scope.loadError = null;
      loadCountries();
      // One metadata check gates the wave: a missing connector or a missing
      // default configuration fails once here (one toast), the widget shows
      // an overlay with the reason, and no section fires its own failing call.
      threatLandscapeViewService.meta().then(function () {
        if (!guard(seq)) { return; }
        loadIndustries();
        loadCards(seq);
        loadKillChain(seq);
        loadTopThreats(seq, $scope.topThreats.exploit);
        loadTopThreats(seq, $scope.topThreats.malware);
        loadCountryList(seq);
        loadIndustryList(seq);
      }).catch(function (err) {
        console.error('[fortiGuardThreatLandscape] setup:', err);
        if (!guard(seq)) { return; }
        $scope.loadError = reasonOf(err) || 'The threat landscape could not be loaded.';
      });
    }

    function loadCountries() {
      return $http.get(widgetBasePath + 'widgetAssets/json/countries.json').then(function (res) {
        $scope.countryOptions = res.data.countries || [];
      }).catch(function (err) {
        console.error('[fortiGuardThreatLandscape] countries.json:', err);
        $scope.countryOptions = $scope.countryOptions || [];
      });
    }

    function loadIndustries() {
      return threatLandscapeViewService.execute('get_industry_list', {}).then(function (res) {
        $scope.industryOptions = (res.data || []).filter(function (i) { return !JUNK_LABELS.test(String(i || '')); });
      }).catch(function (err) {
        console.error('[fortiGuardThreatLandscape] industry list:', err);
        $scope.industryOptions = $scope.industryOptions || [];
      });
    }

    function applyFilters() {
      $scope.showClearFilter = !!($scope.filters.country || $scope.filters.industry);
      $scope.filters.dateRange = _window($scope.filters.dateRange);
      $scope.dateRange = $scope.filters.dateRange;
      // Hide a list the moment it IS the filter, not after the round-trip.
      $scope.topCountries.hidden = !!$scope.filters.country;
      $scope.topIndustries.hidden = !!$scope.filters.industry;
      $scope.drill = null;
      if ($scope.demoMode) { buildDemo(); return; }
      refreshAll();
    }

    function clearFilters() {
      $scope.filters.country = null;
      $scope.filters.industry = null;
      $scope.filters.dateRange = _window(config.time_windows || 7);
      applyFilters();
    }

    function retry() {
      if ($scope.demoMode) { buildDemo(); return; }
      refreshAll();
    }

    /* ================= DEMO MODE ================= */

    // Plausible FortiGuard-shaped numbers with no connector on the box,
    // seeded from the filters so the same view always shows the same numbers,
    // and weighted like the live feed (reconnaissance dwarfs ransomware).
    var DEMO_RATES = {
      'Malicious Activity Detected': 8.6e9,
      'Intrusion Prevention Activity': 8.0e9,
      'Malware Distribution Activity': 1.5e8,
      'Botnet Activity Detected': 1.0e7,
      'Endpoint Activity Detected': 1.1e8
    };
    // [threattype, category label, share of the daily malicious volume]
    var DEMO_KILL_CHAIN = {
      'reconnaissance': [['ips', 'ActiveScan', 1]],
      'weaponization': [],
      'delivery': [['virus', 'DriveByDownload', 0.001], ['virus', 'MalOfficeDocs', 0.001]],
      'exploitation': [['ips', 'BruteForce', 0.05], ['ips', 'Exploitation Attempts', 0.9]],
      'installation': [['virus', 'CryptoMiner', 0.0002], ['virus', 'Trojans', 0.002]],
      'command-and-control': [],
      'actions-on-objectives': [['virus', 'Ransomware', 0.00005], ['ips', 'DenialOfService', 0.08]]
    };
    var DEMO_THREATS = {
      Vulnerability: ['DNS.PTR.Records.Scan', 'HTTP.Suspicious.Headers.With.Special.Characters', 'SIPVicious.SIP.Scanner', 'Modbus.TCP.Unauthorized.Read.Request.PLC', 'TCP.Out.Of.Range.Timestamp'],
      Malware: ['W32/BackDoor.Prosiak', 'HTML/Phish.Tag', 'MSExcel/CVE_2017_0199.Exploit', 'PossibleThreat.RF', 'Riskware/CoinMiner']
    };
    var DEMO_COUNTRIES = ['US', 'VN', 'IN', 'NZ', 'CH', 'ID', 'FR', 'KE', 'BR', 'DE'];
    var DEMO_INDUSTRIES = ['Banking/Finance/Insurance', 'Energy & Utilities', 'Education', 'Agriculture', 'Healthcare', 'Consulting', 'Automotive'];
    var DEMO_OUTBREAKS = [
      ['Refrigeration Control Systems Attack', 'Targeted attacks on industrial refrigeration controllers.'],
      ['PHP2Shell Remote Code Execution', 'Exploitation could allow arbitrary code execution.'],
      ['Node2Shell Remote Code Execution', 'Out-of-bounds write in a widely used decoder.']
    ];

    // xmur3 hash + mulberry32: tiny, deterministic, good enough for demo data.
    function seededRng(seedStr) {
      var h = 1779033703 ^ seedStr.length;
      for (var i = 0; i < seedStr.length; i++) {
        h = Math.imul(h ^ seedStr.charCodeAt(i), 3432918353);
        h = (h << 13) | (h >>> 19);
      }
      var a = (h ^ (h >>> 16)) >>> 0;
      return function () {
        a |= 0; a = (a + 0x6D2B79F5) | 0;
        var t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
    }

    function buildDemo() {
      $scope.showClearFilter = !!($scope.filters.country || $scope.filters.industry);
      $scope.dateRange = $scope.filters.dateRange;
      $scope.loadError = null;
      $scope.asOf = null;
      $scope.drill = null;
      var seed = JSON.stringify([$scope.filters.dateRange, $scope.filters.country, $scope.filters.industry, $scope.demoIntensity]);
      var rng = seededRng(seed);
      var scale = $scope.demoIntensity / 50;
      var win = $scope.filters.dateRange;

      $scope.cards.forEach(function (card) {
        var rate = (DEMO_RATES[card.type] || 1e6) * scale;
        var byWindow = {};
        WINDOWS.forEach(function (w) {
          byWindow[w] = Math.round(rate * w * (0.85 + 0.3 * rng()));
        });
        var count = byWindow[win];
        card.loading = false;
        card.error = null;
        card.data = {
          count: count,
          perDay: count / win,
          trend: win === 21 ? null : {
            percentage: (rng() * 18).toFixed(2),
            direction: rng() < 0.5 ? 'up' : 'down'
          },
          spark: spark(byWindow, true)
        };
      });

      var maxPhase = 0;
      $scope.killChainSections.forEach(function (section) {
        var rate = (DEMO_RATES['Malicious Activity Detected'] || 1e9) * scale;
        section.metrics = (DEMO_KILL_CHAIN[section.id] || []).map(function (c) {
          return { label: c[1], type: c[0], count: Math.round(rate * c[2] * (0.7 + 0.6 * rng())), pct: 0 };
        }).sort(function (a, b) { return b.count - a.count; });
        section.totalCount = section.metrics.reduce(function (sum, m) { return sum + m.count; }, 0);
        maxPhase = Math.max(maxPhase, section.totalCount);
        var phaseMax = section.metrics.reduce(function (m, x) { return Math.max(m, x.count); }, 0) || 1;
        section.metrics.forEach(function (m) { m.pct = Math.max(2, Math.round((m.count / phaseMax) * 100)); });
      });
      $scope.killChainSections.forEach(function (section) {
        section.progressPercent = maxPhase ? (section.totalCount / maxPhase) * 100 : 0;
      });
      $scope.killChain.loading = false;
      $scope.killChain.error = null;

      Object.keys($scope.topThreats).forEach(function (kind) {
        var col = $scope.topThreats[kind];
        var rate = (DEMO_RATES[col.type === 'Malware' ? 'Malware Distribution Activity' : 'Intrusion Prevention Activity'] || 1e6) * scale;
        col.loading = false;
        col.error = null;
        col.items = toRanked(DEMO_THREATS[col.type].map(function (name, i) {
          return {
            Name: name,
            ID: 10000 + Math.floor(rng() * 50000),
            Threattype: col.type === 'Malware' ? 'virus' : 'ips',
            Count: Math.round(rate * win * (0.55 / (i + 1)) * (0.7 + 0.6 * rng()))
          };
        }), 'Name', 5);
      });

      $scope.topCountries = {
        loading: false, error: null,
        hidden: !!$scope.filters.country,
        items: ranked(DEMO_COUNTRIES.map(function (code) {
          return { code: code, title: countryName(code), value: Math.round((DEMO_RATES['Malicious Activity Detected'] || 1e9) * scale * win * 0.5 * (0.4 + rng()) / (DEMO_COUNTRIES.indexOf(code) + 1)) };
        }), 5)
      };
      $scope.topIndustries = {
        loading: false, error: null,
        hidden: !!$scope.filters.industry,
        items: ranked(DEMO_INDUSTRIES.map(function (name) {
          return { code: null, title: name, value: Math.round((DEMO_RATES['Malicious Activity Detected'] || 1e9) * scale * win * 0.5 * (0.4 + rng()) / (DEMO_INDUSTRIES.indexOf(name) + 1)) };
        }), 5)
      };

      $scope.outbreaks = {
        loading: false, error: null,
        items: DEMO_OUTBREAKS.map(function (o, i) {
          var d = new Date(Date.now() - i * 4 * 24 * 3600 * 1000);
          return { name: o[0], subtitle: o[1], date: d.toISOString().split('T')[0], url: null };
        })
      };

      $scope.countryOptions = $scope.countryOptions && $scope.countryOptions.length ? $scope.countryOptions : ['United States', 'India', 'Vietnam', 'Brazil', 'Germany', 'United Kingdom'];
      $scope.industryOptions = $scope.industryOptions && $scope.industryOptions.length ? $scope.industryOptions : DEMO_INDUSTRIES;
    }

    /* ================= INIT ================= */

    function init() {
      var countriesLoad = $http.get(widgetBasePath + 'widgetAssets/lib/iso2_countries.json').then(function (res) {
        $scope.countries = res.data;
      }).catch(function (err) {
        console.error('[fortiGuardThreatLandscape] iso2_countries.json:', err);
      });
      if ($scope.demoMode) {
        buildDemo();
        // The first render may beat the country-name table; the demo is
        // deterministic (same seed), so rebuilding once it arrives only
        // swaps ISO codes for names.
        countriesLoad.then(function () {
          if ($scope.demoMode) { buildDemo(); }
        });
        return;
      }
      refreshAll();
      loadOutbreaks();
    }

    init();
  }
})();
