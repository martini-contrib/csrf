var app = angular.module('app', ['ngCookies']).
run(function($http, $cookies) {
    // Add the header to every post request. 
    // Real code will need to be more robust.
    $http.defaults.headers.post['X-CSRFToken'] = $cookies._csrf;
});

app.controller('protected', function($scope, $http) {
   $scope.result = 'In progress';
   $http.post('/protected', {}).
   success(function(data) {
       $scope.result = data.message;
   }).
   error(function() {
       $scope.result = "Could not complete protected action!";
   });
});
