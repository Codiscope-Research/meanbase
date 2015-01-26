var express = require('express'),
	mongoose = require('mongoose');

// var env = process.env.NODE_ENV = process.env.NODE_ENV || 'development';
var app = express();

var models = require('./database/database')(app, mongoose);
var middleware = require('./config/middleware')(app);
var authentication = require('./authentication/authentication.js')(app, mongoose);
var routes = require('./routes/routes')(app, mongoose, models, authentication.passport);


// Run
app.listen(3000);
console.log('Listening to port ' + 3000 + '...');
