module.exports = function(Schema, models, mongoose) {
	var demoHome = new models.Page({
		author: 'demo',
		visibility: 'Everyone',
		url: '/',
		tabTitle: 'meanbase',
		template: 'front-page',
		title: 'meanbase',
		content: {'content-1': 'Meanbase is a CMS built on the MEAN stack and made to be simple and intuitive for users and developers.'},
		description: 'A demo home page created automatically in meanbase.',
		summary: 'A demo home page created automatically in meanbase.',
		published: true
	});

	// mongoose.model('Page').find({}, function(error, found) {
	// 	if(found.length == 0) {
	// 		demoHome.save(function(error, found) {
	// 			if(error)
	// 				console.log(error);
	// 		});
	// 	}
	// });

};