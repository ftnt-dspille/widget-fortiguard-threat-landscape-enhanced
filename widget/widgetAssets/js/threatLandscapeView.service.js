/* Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end */
'use strict';

(function() {
  angular
    .module('cybersponse')
    .factory('threatLandscapeViewService', threatLandscapeViewService);

  threatLandscapeViewService.$inject = ['API', 'toaster', '$resource', 'connectorService', '$q'];

  function threatLandscapeViewService(API, toaster, $resource, connectorService, $q) {
    var CONNECTOR = 'fortinet-fortiguard-threat-intelligence';
    var metaPromise = null;

    var service = {
        meta: meta,
        execute: execute,
        stats: stats,
        logtime: logtime
    };

    // One metadata lookup per page, not one per call. A failed lookup clears
    // the cache so the next call retries instead of failing forever.
    function meta() {
      if (!metaPromise) {
        metaPromise = $resource(API.INTEGRATIONS + 'connectors/?name=' + CONNECTOR).get().$promise.then(function (connectorMetaDataForVersion) {
          var connector = connectorMetaDataForVersion && connectorMetaDataForVersion.data && connectorMetaDataForVersion.data[0];
          if (!connector) {
            throw notify('The ' + CONNECTOR + ' connector is not installed on this system. Install it from Content Hub, then reload the page.');
          }
          var defaultConfig = (connector.configuration || []).filter(function (item) { return item.default; });
          if (!defaultConfig.length) {
            throw notify('The ' + CONNECTOR + ' connector has no default configuration. Configure it and mark one configuration as default.');
          }
          return { version: connector.version, configId: defaultConfig[0].config_id };
        });
        metaPromise.catch(function () { metaPromise = null; });
      }
      return metaPromise;
    }

    function execute(connector_action, payload) {
      return meta().then(function (m) {
        return connectorService.executeConnectorAction(CONNECTOR, m.version, connector_action, m.configId, payload);
      })
      .catch(function (error) {
        console.error('[fortiGuardThreatLandscape] request failed:', error);
        if (!(error && error.notified)) {
          var reason = error && (error.message || (error.data && (error.data.message || error.data.error)));
          toaster.error({ body: 'The ' + CONNECTOR + ' request failed' + (reason ? ': ' + reason : '.') });
        }
        throw error; // Rethrow the error to be handled by the caller
      });
    }

    // Stats rows of a feed response, or [].
    function stats(res) {
      return (res && res.data && res.data[0] && res.data[0].Stats) || [];
    }

    // Feed timestamp of a response ("2026-11-19 00:44", UTC), or null.
    function logtime(res) {
      return (res && res.data && res.data[0] && res.data[0].Logtime) || null;
    }

    function notify(message) {
      toaster.error({ body: message });
      var err = new Error(message);
      err.notified = true;
      return err;
    }

    return service;
  }
})();
