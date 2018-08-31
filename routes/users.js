var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var bcrypt = require('bcryptjs');

var User = require('../models/user');

// Register
router.get('/register', function(req, res) {
	res.render('register', {
		user: req.user
	});
});
// Login
router.get('/login', function(req, res) {
	res.render('login', {
		user: req.user
	});
	console.log('user', req.user);
});

router.get('/forgot', function(req, res) {
	res.render('forgot', {
		user: req.user
	});
});
//reset password
router.get('/reset/:token', function(req, res) {
	User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(
		err,
		user
	) {
		if (!user) {
			req.flash('error', 'Password reset token is invalid or has expired.');
			return res.redirect('/forgot');
		}
		res.render('reset', {
			user: req.user
		});
	});
});

// Register User
router.post('/register', function(req, res) {
	console.log('body', req.body);
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var confirmpassword = req.body.confirm;

	// Validation
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('confirm', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();
	console.log(errors);
	if (errors) {
		for (var i = 0; i < errors.length; i++) {
			req.flash('error', errors[i].msg);
		}
		res.render('register');
	} else {
		//checking for email and username are already taken
		User.findOne(
			{
				username: {
					$regex: '^' + username + '\\b',
					$options: 'i'
				}
			},
			function(err, user) {
				User.findOne(
					{
						email: {
							$regex: '^' + email + '\\b',
							$options: 'i'
						}
					},
					function(err, mail) {
						if (user || mail) {
							req.flash('error', 'Username or Email already exist.');
							res.render('register', {
								user: user,
								mail: mail
							});
						} else {
							var newUser = new User({
								email: email,
								username: username,
								password: password
							});
							User.createUser(newUser, function(err, user) {
								if (err) throw err;
								console.log('user created', user);
							});
							req.flash('success', 'You are registered and can now login');
							res.redirect('/users/login');
						}
					}
				);
			}
		);
	}
});

passport.use(
	new LocalStrategy(function(username, password, done) {
		User.getUserByUsername(username, function(err, user) {
			if (err) throw err;
			if (!user) {
				return done(null, false, { message: 'Unknown User' });
			}

			User.comparePassword(password, user.password, function(err, isMatch) {
				if (err) throw err;
				if (isMatch) {
					return done(null, user);
				} else {
					return done(null, false, { message: 'Invalid password' });
				}
			});
		});
	})
);

passport.serializeUser(function(user, done) {
	done(null, user.id);
});

passport.deserializeUser(function(id, done) {
	User.getUserById(id, function(err, user) {
		done(err, user);
	});
});

router.post(
	'/login',
	passport.authenticate('local', { successRedirect: '/', failureRedirect: '/users/login', failureFlash: true }),
	function(req, res) {
		res.status(200);
	}
);

router.get('/logout', function(req, res) {
	console.log('logout callled');
	req.logout();

	req.flash('success', 'You are logged out');
	res.redirect('/');
});

router.post('/forgot', function(req, res, next) {
	async.waterfall(
		[
			function(done) {
				crypto.randomBytes(20, function(err, buf) {
					var token = buf.toString('hex');
					done(err, token);
				});
			},
			function(token, done) {
				User.findOne({ email: req.body.email }, function(err, user) {
					if (!user) {
						req.flash('error', 'No account with that email address exists.');
						return res.redirect('/users/forgot');
					}

					user.resetPasswordToken = token;
					user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

					user.save(function(err) {
						done(err, token, user);
					});
				});
			},
			function(token, user, done) {
				var smtpTransport = nodemailer.createTransport({
					service: 'SendGrid',
					auth: {
						user: 'shyamamrtiya',
						pass: 'Suitar@12'
					}
				});
				var mailOptions = {
					to: user.email,
					from: 'ch2shi3w6jdxfcx2@ethereal.email',
					subject: 'Node.js Password Reset',
					text:
						'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
						'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
						'http://' +
						req.headers.host +
						'/users/reset/' +
						token +
						'\n\n' +
						'If you did not request this, please ignore this email and your password will remain unchanged.\n'
				};
				smtpTransport.sendMail(mailOptions, function(err) {
					req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
					done(err, 'done');
				});
			}
		],
		function(err) {
			console.log(err);
			if (err) return next(err);
			res.redirect('/users/forgot');
		}
	);
});

router.post('/reset/:token', function(req, res) {
	async.waterfall(
		[
			function(done) {
				User.findOne(
					{ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } },
					function(err, user) {
						if (!user) {
							req.flash('error', 'Password reset token is invalid or has expired.');
							return res.redirect('/users/forgot');
						}

						bcrypt.genSalt(10, function(err, salt) {
							bcrypt.hash(req.body.password, salt, function(err, hash) {
								user.password = hash;
								user.resetPasswordToken = undefined;
								user.resetPasswordExpires = undefined;
								console.log('pass', user.password);
								user.save(function(err) {
									req.logIn(user, function(err) {
										console.log('logged in');
										done(err, user);
									});
								});
							});
						});
					}
				);
			},
			function(user, done) {
				var smtpTransport = nodemailer.createTransport({
					service: 'SendGrid',
					auth: {
						user: 'shyamamrtiya',
						pass: 'Suitar@12'
					}
				});
				var mailOptions = {
					to: user.email,
					from: 'ch2shi3w6jdxfcx2@ethereal.email',
					subject: 'Your password has been changed',
					text:
						'Hello,\n\n' +
						'This is a confirmation that the password for your account ' +
						user.email +
						' has just been changed.\n'
				};
				smtpTransport.sendMail(mailOptions, function(err) {
					req.flash('success', 'Success! Your password has been changed.');
					done(err);
				});
			}
		],
		function(err) {
			res.redirect('/');
		}
	);
});
module.exports = router;
