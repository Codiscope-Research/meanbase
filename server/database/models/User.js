var bcrypt = require('bcrypt-nodejs');

module.exports = function(Schema, models, validate, mongoose) {
	// Users
	var usersSchema = new Schema({
		username: {
			type: String,
			trim: true,
			unique: true,
			validate: validate.username
		},
		email: {
	        type: String,
	        trim: true,
	        unique: true,
	        validate: validate.email,
	        required: 'Email address is required'
		},
		password: {
			type: String,
			required: true
		},
		access: {
			type:Schema.ObjectId, 
			ref: 'Role',
			required: true
		},
		signedIn: {
			type: Boolean,
			default: true
		},
		gravatar: String,
		active: {
			type: Boolean,
			default: true
		},
		meta: Object,
		lastVisited: {
			type: Date, 
			default: Date.now
		}
	});

	// generating a hash
	usersSchema.methods.generateHash = function(password) {
	    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
	};

	// checking if password is valid
	usersSchema.methods.validPassword = function(password) {
	    return bcrypt.compareSync(password, this.password);
	};


	return mongoose.model('User', usersSchema);
};