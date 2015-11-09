var codes = new Meteor.Collection('meteor_accounts_tfa');

Meteor.methods({
  "tfa.validateUserAndSendCode" : function( username, passwordDigest) {
    check(username, String);
    check(passwordDigest, passwordValidator);
    Accounts.tfa.validateUserAndSendCode(username , passwordDigest)
  },
  "tfa.sendCodeBeforeRegister" : function( username ) {
    console.log("#sendCodeBeforeRegister method called" , username);
    if (username.indexOf('@') === -1) {
      user = Meteor.users.findOne({ username: username });
      if(!user) throw new Meteor.Error('Username \''+username+'\' doesn\'t exists, enter your email address to create your account instead of your username.');
      if(!user.emails || user.emails.length < 1) throw new Meteor.Error('No email attached to user ' + username);
      email = user.emails[0].address;
    } else {
      user = Meteor.users.findOne({ 'emails.address': username });
      // If the user doesn't exists, we'll create it when the user will verify his email
      email = username;
    }
    sendVerifyCode(user , email);
  }
});

Accounts.tfa.validateUserAndSendCode = function ( username , passwordDigest ) {
  var email;
  var user;

  // Lets check if the username is email or not

  if (username.indexOf('@') === -1) {
    user = Meteor.users.findOne({ username: username });
    if(!user) throw new Meteor.Error('Username \''+username+'\' doesn\'t exists, enter your email address to create your account instead of your username.');
    if(!user.emails || user.emails.length < 1) throw new Meteor.Error('No email attached to user ' + username);
    email = user.emails[0].address;
  } else {
    user = Meteor.users.findOne({ 'emails.address': username });
    // If the user doesn't exists, we'll create it when the user will verify his email
    email = username;
  }

  // Lets confirm if the user/password combo is right

  var user = Meteor.users.findOne({ '$or': [{'username': username},{'emails.address': username}]});
  if ( !user )
    throw new Meteor.Error(404,'fail');

  // 2. User exists, lets check the password
  var password = {digest: passwordDigest, algorithm: 'sha-256'};

  var pswdCheck = Accounts._checkPassword(user, password);
  if (pswdCheck.error)
      throw new Meteor.Error(403,'fail');

  //3. Authenticate directly if 2FA is disabled.

  //override :
  sendVerifyCode(user , email);
}

Accounts.registerLoginHandler('tfa' , function(loginRequest) {
  console.log("#Registered: twoFactorAuth Login Handler");
  console.log("# Login Request: " , loginRequest);

  if(!loginRequest.username) {
    return undefined;
  }
  if(!loginRequest.code) {
    return undefined;
  }


  check(loginRequest, {
    username: String,
    code: String
  });

  return Accounts.tfa.loginUserWithTFA(loginRequest)

})




Accounts.tfa.loginUserWithTFA = function(loginRequest) {

  var selector = loginRequest.username;
  var email;
  var user;

  if (selector.indexOf('@') === -1) {
      user = Meteor.users.findOne({ username: selector });
      if(!user) throw new Meteor.Error('Username \''+selector+'\' doesn\'t exists, enter your email address to create your account instead of your username.');
      if(!user.emails || user.emails.length < 1) throw new Meteor.Error('No email attached to user ' + selector);
      email = user.emails[0].address;
  } else {
      user = Meteor.users.findOne({ 'emails.address': selector });

      email = selector;
  }

  var validCode = codes.findOne({ email: email});
  if (!validCode)
    throw new Meteor.Error('Unknown email');

  var now = new Date().getTime() / 1000;
  var timeToWait;

  if (validCode.lastTry) {
    timeToWait = validCode.lastTry.getTime()/1000 + Math.pow(validCode.nbTry, 2);

    if (timeToWait > now)
      throw new Meteor.Error('You must wait ' + Math.ceil(timeToWait - now) + ' seconds');
  }

  if (validCode.code !== loginRequest.code) {
    codes.update({email: email}, { $set: {lastTry: new Date()}, $inc: {nbTry: 1 }});
    throw new Meteor.Error('Invalid verification code');
  }
  // Clear the verification code after a succesful login.
  console.log("removing code for email: ", email);

  codes.remove({ email: email });

  var uid;
  if(user) {
    uid = user._id;
  } else {
    uid = createUser({ email: email });
    user = Meteor.users.findOne(uid);
    console.log('created user', uid, user);
  }

  if(user) {
    var ve = _.find(user.emails, function (e) { return e.address === email; });
    if(ve && !ve.verified) {
      Meteor.users.update({ _id: uid, 'emails.address': email }, { $set: { 'emails.$.verified': true } });
    }
  }
  return { userId: uid };
};


Accounts.validateLoginAttempt(function(attempt){
  var allowed = [
        'login',
        'createUser',
        'verifyEmail',
        'resetPassword',
        'changePassword'
    ];
  if ((_.contains(allowed, attempt.methodName) && attempt.type == 'resume') || attempt.type === 'tfa'){

      return true;
  }

  if ( attempt.type === 'password' && attempt.methodName === 'createUser') {
    //Register new user
    return true;
  }
  return false;
});

// Validate new users
// This has to be on the client be
Accounts.validateNewUser(function (user) {
  // Ensure user name is long enough
  if (user.username.length < 8) {
    throw new Meteor.Error(403, 'Your username needs at least 8 characters');
  }
  return true;
});


// Helper functions
var NonEmptyString = Match.Where(function (x) {
  check(x, String);
  return x.length > 0;
});

var userQueryValidator = Match.Where(function (user) {
  check(user, {
    id: Match.Optional(NonEmptyString),
    username: Match.Optional(NonEmptyString),
    email: Match.Optional(NonEmptyString)
  });

  if (_.keys(user).length !== 1)
    throw new Match.Error("User property must have exactly one field");
  return true;
});

var passwordValidator = Match.OneOf(
  String,
  { digest: String, algorithm: String }
);


var saveLoginToken = function(userId){
    return Meteor.wrapAsync(function(userId, tokens, cb){
        // In tokens array first is stamped, second is hashed
        // Save hashed to Mongo
        Meteor.users.update(userId, {
            $push: {
                'services.resume.loginTokens': tokens[1]
            }
        }, function(error){
            if (error){
                cb(new Meteor.Error(500, 'Couldnt save login token into user profile'));
            }else{
                // Return stamped to user
                cb && cb(null, [200,tokens[0].token]);
            }
        });
    })(userId, generateLoginToken());
};

var generateLoginToken = function(){
    var stampedToken = Accounts._generateStampedLoginToken();
    return [
        stampedToken,
        Accounts._hashStampedToken(stampedToken)
    ];
};

var sendVerifyCode = function(user , email) {
  user.twoFactorEnabled = true;
  if (!user.twoFactorEnabled){
      //Use function defined above
      return saveLoginToken(user._id);
    } else {
      var code = Math.floor(Random.fraction() * 10000) + '';
      // force pin to 4 digits
      code = ('0000' + code).slice(-4);

      // Generate a new code
      console.log("Inserting code for email : ", email);
      codes.upsert({ email: email }, { $set: { code: code }});

    //  console.log("The CODE is : " , code );

      Meteor.call("TwoFactorAuth.SendCode" , user , code, function(err , res) {
        if(err) {
          console.log("There was an error calling the method : TwoFactorAuth.SendCode", err);
        } else {
          console.log("Successfully transferred the job of sending the code to App Server Method: TwoFactorAuth.SendCode")
        }
      })

      // Email.send({
      //   to: email,
      //   from: Accounts.passwordless.emailTemplates.from,
      //   subject: Accounts.passwordless.emailTemplates.sendVerificationCode.subject(code),
      //   text: Accounts.passwordless.emailTemplates.sendVerificationCode.text(user, code, selector, options)
      // });
  }
}
