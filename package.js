Package.describe({
  name: 'azfx:twofactorauth',
  version: '0.0.1',
  // Brief, one-line summary of the package.
  summary: 'Two Factor Auth for Meteor',
  // URL to the Git repository containing the source code for this package.
  git: '',
  // By default, Meteor will default to using README.md for documentation.
  // To avoid submitting documentation, set this field to null.
  documentation: 'README.md'
});

Package.onUse(function(api) {
  api.versionsFrom('1.2.0.2');
  api.use('ecmascript');
  api.use(['tracker', 'underscore', 'templating', 'session' , 'blaze-html-templates'], 'client');
  api.use('email', 'server');
  api.use(['accounts-base', 'accounts-password', 'check' , 'sha'], ['client', 'server']);

  // Export Accounts (etc) to packages using this one.
  api.imply('accounts-base', ['client', 'server']);

  api.addFiles('twofactorauth.js');
  api.addFiles('twofactorauth-client.js' , 'client');
  api.addFiles('twofactorauth-server.js' , 'server');
});
