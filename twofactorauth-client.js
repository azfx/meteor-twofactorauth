Meteor.loginWithTwoFactorAuth = function (options, callback) {
  console.log('loginWithTwoFactorAuth', options);
  Accounts.callLoginMethod({
    methodArguments: [{
      username: options.username,
      code: options.code
    }],
    userCallback: callback
  });
};


Meteor.validateUserAndSendCode = function (username, password, callback) {
  // Save the selector in a Session so even if the client reloads, the selector is stored
  Session.set('tfa.username', username);

  var passwordDigest = Package.sha.SHA256(password);

  Meteor.call('tfa.validateUserAndSendCode', username, passwordDigest, callback);
};

Meteor.sendCodeBeforeRegister = function (username, options , callback) {
  Session.set('tfa.username' , username);
  Accounts.createUser(options, function( err, success){
     if(err) {
       Session.set('tfaMessage', err.reason);
       if ( err.reason === "Login forbidden") {
         Session.set('tfaState', 'tfaVerify');
         Meteor.call('tfa.sendCodeBeforeRegister' , username , callback);
       }
     }
  });
}
