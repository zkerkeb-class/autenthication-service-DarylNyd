const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { isAuthenticated } = require('../middleware/auth');
const { loginLimiter, passwordResetLimiter, authLimiter } = require('../middleware/rateLimit');
const passport = require('passport');

// Local authentication routes with rate limiting
router.post('/register', authLimiter, authController.register);
router.post('/login', loginLimiter, authController.login);
router.post('/refresh-token', authLimiter, authController.refreshToken);
router.post('/logout', isAuthenticated, authController.logout);
router.post('/forgot-password', passwordResetLimiter, authController.forgotPassword);
router.post('/reset-password', passwordResetLimiter, authController.resetPassword);
router.get('/me', isAuthenticated, authController.getCurrentUser);

// Google OAuth routes
router.get('/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback',
    passport.authenticate('google', { session: false }),
    (req, res) => {
        if (!req.user) {
            console.error('Google OAuth authentication failed - no user data');
            return res.redirect(`${process.env.CLIENT_URL}/auth-success?error=authentication_failed`);
        }
        
        try {
            const token = authController.generateToken(req.user);
            // Redirect to frontend auth-success page
            res.redirect(`${process.env.CLIENT_URL}/auth-success?token=${encodeURIComponent(token)}`);
        } catch (error) {
            console.error('Error generating token for Google OAuth:', error);
            res.redirect(`${process.env.CLIENT_URL}/auth-success?error=token_generation_failed`);
        }
    }
);

// Health check endpoint
router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'auth-service',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

module.exports = router; 