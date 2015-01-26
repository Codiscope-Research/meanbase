var passport = require('passport'),
	LocalStrategy = require('passport-local').Strategy,
	session = require('express-session');

module.exports = function(app, mongoose) {

	app.use(session({
		secret: 'Yellow or*&ange bRown_189', 
		resave: false, 
		'saveUninitialized': true
	}));
	
	app.use(passport.initialize());
	app.use(passport.session());

	passport.use(new LocalStrategy(
		function(username, password, done) {
			mongoose.model('User').findOne({username: username}, function(error, user) {
				if (error) { return done(error); }
				if (!user) { return done(null, false); }
				if (!user.verifyPassword(password)) { return done(null, false); }
				return done(null, user);
			});			
		}
	));

	passport.serializeUser(function(user, done) {
        done(null, user._id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(_id, done) {
        mongoose.model('User').findById(_id, function(err, user) {
            done(err, user);
        });
    });

    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    }, function(req, email, password, done) { // callback with email and password from our form

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        mongoose.model('User').findOne({'email': email}, function(error, user) {
            // if there are any errors, return the error before anything else
            if (error)
                return done(error);

            // if no user is found, return the message
            if (!user)
                return done(null, false);

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false);

            // all is well, return successful user
            return done(null, user);
        });
    }));



    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    }, function(req, email, password, done) {

        // asynchronous
        // User.findOne wont fire unless data is sent back
        process.nextTick(function() {

        	// find a user whose email is the same as the forms email
        	// we are checking to see if the user trying to login already exists
	    	mongoose.model('User').findOne({'email': email}, function(error, user) {
	            // if there are any errors, return the error
	            if (error)
	                return done(error);

	            // check to see if there's already a user with that email
	            if (user) {
	                return done(null, false);
	            } else {
	                // if there is no user with that email
	                // create the user
	                var newUser = new models.User({
						email: email,
						password: mongoose.model('User').generateHash(password)
	                });

	                // save the user
	                newUser.save(function(error, found) {
						if (error)
							throw error;
						return done(null, newUser);
					});
	            } // if user found
	        }); //findOne (check to see if user already exists) 
        }); //nextTick()
    })); //callback




	return {
		passport: passport,
		isLoggedIn: function(req, res, next) {
			if (req.isAuthenticated())
	        	return next();
			 // if they aren't logged in redirect them to the home page
	    	res.render('cms/templates/front-end/mb-login');
		}
	}
};