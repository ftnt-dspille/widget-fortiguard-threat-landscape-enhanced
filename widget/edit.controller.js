/* Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end */
'use strict';
(function () {
    angular
        .module('cybersponse')
        .controller('editFortiGuardThreatLandscape104DevCtrl', editFortiGuardThreatLandscape104DevCtrl);

    editFortiGuardThreatLandscape104DevCtrl.$inject = ['$scope', '$uibModalInstance', 'config'];

    function editFortiGuardThreatLandscape104DevCtrl($scope, $uibModalInstance, config) {
        $scope.cancel = cancel;
        $scope.save = save;
        // An array, not an object: ng-options sorts object keys alphabetically,
        // which would order the dropdown 1, 14, 21, 3, 7.
        $scope.intervalOptions = [
            { label: 'Last 1 Day', value: 1 },
            { label: 'Last 3 Days', value: 3 },
            { label: 'Last 7 Days', value: 7 },
            { label: 'Last 14 Days', value: 14 },
            { label: 'Last 21 Days', value: 21 }
        ];
        let defaultConfig = {
            time_windows: 14,
            demoMode: false,
            demoIntensity: 50
        };

        $scope.config = config;
        $scope.config.time_windows = $scope.config.time_windows || defaultConfig.time_windows;
        if ($scope.config.demoMode === undefined) { $scope.config.demoMode = defaultConfig.demoMode; }
        if (!$scope.config.demoIntensity) { $scope.config.demoIntensity = defaultConfig.demoIntensity; }

        function cancel() {
            $uibModalInstance.dismiss('cancel');
        }

        function save() {
            $uibModalInstance.close($scope.config);
        }

    }
})();
