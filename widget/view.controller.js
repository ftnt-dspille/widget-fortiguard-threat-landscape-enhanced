/* Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end */
'use strict';

(function () {
  angular
    .module('cybersponse')
    .controller('fortiGuardThreatLandscape102DevCtrl', fortiGuardThreatLandscape102DevCtrl);

  fortiGuardThreatLandscape102DevCtrl.$inject = ['$scope', '$rootScope', '$http', 'threatLandscapeViewService', 'widgetTemplateService', 'widgetService', 'config', 'widgetBasePath', 'translationService'];

  function fortiGuardThreatLandscape102DevCtrl($scope, $rootScope, $http, threatLandscapeViewService, widgetTemplateService, widgetService, config, widgetBasePath, translationService) {

    /* ================= BASE CONFIG ================= */

    $scope.theme = $rootScope.theme.id;
    $scope.config = config;
    $scope.widgetBasePath = widgetBasePath;
    $scope.widgetCSS = widgetBasePath + 'widgetAssets/css/threatLandscapeView.css';

    $scope.widgetProcessing = false;
    $scope.model = {};
    $scope.widgetDefinition = {};
    $scope.showClearFilter = false;
    $scope.clearFilters = clearFilters;

    /* ================= FILTERS ================= */

    $scope.filters = {
      dateRange: config.time_windows || 7,
      industry: null,
      country: null
    };
    $scope.dateRange = angular.copy($scope.filters.dateRange);

    $scope.dateRanges = {
      'Last 1 Day': 1,
      'Last 3 Days': 3,
      'Last 7 Days': 7,
      'Last 14 Days': 14,
      'Last 21 Days': 21
    };

    $scope.industryOptions = [];
    $scope.countryOptions = [];

    /* ================= TREND SUMMARY ================= */

    $scope.trendSummaryConfig = {
      title: 'Threat Landscape View',
      cards: {
        ips_malicious: createCard('threatLandscapeView.TITLE_IPS_MALICIOUS', 'Malicious Activity Detected', 'threatLandscapeView.TOOLTIP_IPS_MALICIOUS'),
        ips_intrusion: createCard('threatLandscapeView.TITLE_IPS_INTRUSION', 'Intrusion Prevention Activity', 'threatLandscapeView.TOOLTIP_IPS_INTRUSION', 'IPS'),
        av_malware: createCard('threatLandscapeView.TITLE_AV_MALWARE', 'Malware Distribution Activity', 'threatLandscapeView.TOOLTIP_AV_MALWARE', 'AV'),
        c2_botnet: createCard('threatLandscapeView.TITLE_C2_BOTNET', 'Botnet Activity Detected', 'threatLandscapeView.TOOLTIP_C2_BOTNET', 'C2')
      }
    };

    function createCard(title, action, tooltip, icon) {
      return { title, action, tooltip, icon, loading: true, data: null };
    }

    /* ================= KILL CHAIN ================= */

    $scope.killChainSections = [
      {
        id: 'reconnaissance',
        title: 'Reconnaissance',
        metrics: []
      },
      {
        id: 'weaponization',
        title: 'Weaponization',
        metrics: []
      },
      {
        id: 'delivery',
        title: 'Delivery',
        metrics: []
      },
      {
        id: 'exploitation',
        title: 'Exploitation',
        metrics: []
      },
      {
        id: 'installation',
        title: 'Installation',
        metrics: []
      },
      {
        id: 'command-and-control',
        title: 'Command & Control',
        metrics: []
      },
      {
        id: 'actions-on-objectives',
        title: 'Actions on Objectives',
        metrics: []
      }
    ];


    /* ================= API HELPERS ================= */

    function getActionByFilter() {
      if ($scope.filters.industry && $scope.filters.country) {
        return 'threat_activities_statistics_by_country_and_industry';
      }
      if ($scope.filters.industry) {
        return 'threat_activities_statistics_by_industry';
      }
      if ($scope.filters.country) {
        return 'threat_activities_statistics_by_country';
      }
      return 'threat_activities_statistics';
    }

    function getKillChainActionByFilter() {
      if ($scope.filters.industry && $scope.filters.country) {
        return 'kill_chain_metrics_country_industry';
      }
      if ($scope.filters.industry) {
        return 'kill_chain_metrics_industry';
      }
      if ($scope.filters.country) {
        return 'kill_chain_metrics_country';
      }
      return 'kill_chain_metrics';
    }

    function buildParams(card) {
      const params = {
        threat_type: card.action,
        time_windows: $scope.filters.dateRange
      };
      if ($scope.filters.industry) {
        params.industry = $scope.filters.industry;
      }
      if ($scope.filters.country) {
        params.country = $scope.filters.country;
      }
      return params;
    }

    function buildKillChainParams() {
      const params = {
        time_windows: $scope.filters.dateRange
      };
      if ($scope.filters.industry) {
        params.industry = $scope.filters.industry;
      }
      if ($scope.filters.country) {
        params.country = $scope.filters.country;
      }
      return params;
    }

    function updateCard(cardId, action) {
      const card = $scope.trendSummaryConfig.cards[cardId];
      if (!card) {
        return;
      }

      card.loading = true;

      return threatLandscapeViewService.executeAction('fortinet-fortiguard-threat-intelligence', action, buildParams(card)).then(res => {
        card.data = res?.data?.[0]?.Stats?.[0] || {};
      }).finally(() => {
        card.loading = false;
      });
    }

    function loadTrendSummary() {
      const action = getActionByFilter();
      angular.forEach($scope.trendSummaryConfig.cards, (_, id) => {
        updateCard(id, action);
      });
    }

    /* ================= KILL CHAIN LOGIC ================= */

    function calculatePhaseProgress() {
      let maxValue = 0;

      $scope.killChainSections.forEach(section => {
        section.totalValue = section.metrics.reduce(
          (sum, m) => sum + Number(m.Count || 0),
          0
        );
        maxValue = Math.max(maxValue, section.totalValue);
      });

      $scope.maxPhaseValue = maxValue;

      $scope.killChainSections.forEach(section => {
        section.progressPercent = maxValue
          ? (section.totalValue / maxValue) * 100
          : 0;
      });
    }

    function buildKillChainWidget() {
      $scope.widgetProcessing = true;

      widgetService.getInstalledWidgets().then(widgets => {
        const widget = widgets.find(w => w.name === 'killchainphases');
        if (!widget) {  
          return;
        }
        $scope.widgetDefinition.killchainphases = widgetTemplateService.generateWidgetDefinition(widget);
        $scope.model.killchainphases = {
          config: {
            data: $scope.killChainSections,
            showMetrics: true,
            title: 'Kill Chain Stages'
          }
        };
      }).finally(() => {
        $scope.widgetProcessing = false;
      });
    }

    function clearFilters() {
      $scope.filters.country = null;
      $scope.filters.industry = null;
      $scope.filters.dateRange = $scope.config.time_windows;
      $scope.dateRange = angular.copy($scope.filters.dateRange);
      $scope.showClearFilter = false;
      loadTrendSummary();
      loadKillChainDetails();
    }

    /* ================= LOAD COUNTRIES AND INDUSTRIES ================= */

    function loadCountries() {
      return $http.get(widgetBasePath + 'widgetAssets/json/countries.json').then(res => {
        $scope.countryOptions = res.data.countries || [];
      });
    }

    function loadIndustries() {

      return threatLandscapeViewService.executeAction('fortinet-fortiguard-threat-intelligence', 'get_industry_list', {}).then(res => {
        $scope.industryOptions = res.data || [];
      });
    }

    /* ================= LOAD KILL CHAIN DETAILS ================= */
    function loadKillChainDetails() {
      const action = getKillChainActionByFilter();
      return threatLandscapeViewService.executeAction('fortinet-fortiguard-threat-intelligence', action, buildKillChainParams()).then(res => {
        const apiResponseData = res.data || [];
        $scope.killChainSections.forEach(section => {
            const matchedStage = apiResponseData.length > 0 ? apiResponseData.find(item => item.id === section.id) : {};
            if (matchedStage && matchedStage.metrics) {
                section.metrics = matchedStage.metrics;
                section.totalCount = matchedStage.metrics.reduce((sum, m) => sum + m.Count, 0);
            } else {
                section.metrics = [];
                section.totalCount = 0;
            }
        });
        calculatePhaseProgress();
        buildKillChainWidget();
      });
    }

    /* ================= PUBLIC ================= */

    $scope.applyFilters = function() {
      $scope.showClearFilter = !!($scope.filters.country || $scope.filters.industry);
      $scope.dateRange = angular.copy($scope.filters.dateRange);
      loadTrendSummary();
      loadKillChainDetails();
    };

    /* ================= INIT ================= */

    function init() {
      loadCountries();
      loadIndustries();
      loadTrendSummary();
      loadKillChainDetails();
    }

    init();
  }
})();
