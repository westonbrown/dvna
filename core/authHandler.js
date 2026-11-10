var db = require('../models')
var bCrypt = require('bcrypt')
var crypto = require('crypto')

var resetKey = crypto.randomBytes(32)

function makeResetToken(user, expires) {
	return expires + '.' + crypto.createHmac('sha256', resetKey).update(user.login + '|' + expires + '|' + user.password).digest('hex')
}

function validResetToken(user, token) {
	if (typeof token !== 'string') return false
	var expires = parseInt(token.split('.')[0], 10)
	if (!(expires > Date.now())) return false
	var expected = Buffer.from(makeResetToken(user, expires))
	var given = Buffer.from(token)
	return expected.length === given.length && crypto.timingSafeEqual(expected, given)
}

module.exports.isAuthenticated = function (req, res, next) {
	if (req.isAuthenticated()) {
		req.flash('authenticated', true)
		return next();
	}
	res.redirect('/login');
}

module.exports.isAdmin = function (req, res, next) {
	if (req.isAuthenticated() && req.user.role == 'admin') {
		return next();
	}
	res.status(403).json({
		success: false,
		message: 'Forbidden'
	})
}

module.exports.isNotAuthenticated = function (req, res, next) {
	if (!req.isAuthenticated())
		return next();
	res.redirect('/learn');
}

module.exports.isAdmin = function (req, res, next) {
	if (req.user && req.user.role == 'admin')
		return next();
	if (req.accepts(['html', 'json']) == 'json')
		return res.status(403).json({
			success: false
		});
	res.redirect('/app/admin');
}

module.exports.forgotPw = function (req, res) {
	if (req.body.login) {
		db.User.find({
			where: {
				'login': req.body.login
			}
		}).then(user => {
			if (user) {
					// Send reset link via email happens here, carrying this token
					var resetToken = makeResetToken(user, Date.now() + 60 * 60 * 1000)
			}
			req.flash('info', 'If the account exists, check email for reset link')
			res.redirect('/login')
		})
	} else {
		req.flash('danger', "Invalid login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPw = function (req, res) {
	if (req.query.login) {
		db.User.find({
			where: {
				'login': req.query.login
			}
		}).then(user => {
			if (user) {
				if (validResetToken(user, req.query.token)) {
					res.render('resetpw', {
						login: req.query.login,
						token: req.query.token
					})
				} else {
					req.flash('danger', "Invalid reset token")
					res.redirect('/forgotpw')
				}
			} else {
				req.flash('danger', "Invalid login username")
				res.redirect('/forgotpw')
			}
		})
	} else {
		req.flash('danger', "Non Existant login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPwSubmit = function (req, res) {
	if (req.body.password && req.body.cpassword && req.body.login && req.body.token) {
		if (req.body.password == req.body.cpassword) {
			db.User.find({
				where: {
					'login': req.body.login
				}
			}).then(user => {
				if (user) {
					if (validResetToken(user, req.body.token)) {
						user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
						user.save().then(function () {
							req.flash('success', "Passowrd successfully reset")
							res.redirect('/login')
						})
					} else {
						req.flash('danger', "Invalid reset token")
						res.redirect('/forgotpw')
					}
				} else {
					req.flash('danger', "Invalid login username")
					res.redirect('/forgotpw')
				}
			})
		} else {
			req.flash('danger', "Passowords do not match")
			res.render('resetpw', {
				login: req.query.login,
				token: req.query.token
			})
		}

	} else {
		req.flash('danger', "Invalid request")
		res.redirect('/forgotpw')
	}
}