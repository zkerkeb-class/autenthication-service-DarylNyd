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
    async (req, res) => {
        if (!req.user) {
            console.error('Google OAuth authentication failed - no user data');
            return res.redirect(`${process.env.CLIENT_URL}/auth-success?error=authentication_failed`);
        }
        
        try {
        const token = authController.generateToken(req.user);
            
            // Send welcome email for new users (check if user was recently created)
            // We'll check if the user was created within the last few seconds
            const userCreatedRecently = req.user.createdAt && 
                (new Date() - new Date(req.user.createdAt)) < 10000; // 10 seconds
            
            if (userCreatedRecently) {
                try {
                    const loginLink = `${process.env.CLIENT_URL || 'http://localhost:3000'}/login`;
                    const response = await fetch('http://localhost:4003/welcome', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            email: req.user.email, 
                            username: req.user.username,
                            loginLink 
                        })
                    });

                    if (!response.ok) {
                        console.error('Notification service returned error for welcome email:', response.status, response.statusText);
                    } else {
                        const result = await response.json();
                        console.log('Welcome email sent successfully for Google OAuth user:', result);
                    }
                } catch (emailError) {
                    console.error('Failed to call notification service for welcome email:', emailError);
                    // Don't fail the OAuth flow if email fails, just log it
                }
            }
            
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

// Update user's current plan
router.patch('/users/:userId/plan', authController.updateUserPlan);

module.exports = router; 