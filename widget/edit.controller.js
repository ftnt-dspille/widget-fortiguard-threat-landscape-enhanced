/* Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end */
'use strict';
(function () {
    angular
        .module('cybersponse')
        .controller('editFortiGuardThreatLandscape102DevCtrl', editFortiGuardThreatLandscape102DevCtrl);

    editFortiGuardThreatLandscape102DevCtrl.$inject = ['$scope', '$uibModalInstance', 'config'];

    function editFortiGuardThreatLandscape102DevCtrl($scope, $uibModalInstance, config) {
        $scope.cancel = cancel;
        $scope.save = save;
        $scope.intervalOptions = {
          'Last 1 Day': 1,
          'Last 3 Days': 3,
          'Last 7 Days': 7,
          'Last 14 Days': 14,
          'Last 21 Days': 21
        };
        let defaultConfig = {
          time_windows: 14
        };

        $scope.config = config;
        $scope.config.time_windows = $scope.config.time_windows || defaultConfig.time_windows;

        function cancel() {
            $uibModalInstance.dismiss('cancel');
        }

        function save() {
            $uibModalInstance.close($scope.config);
        }

    }
})();
