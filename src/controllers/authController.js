const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const DatabaseService = require('../services/dbService');
const EmailService = require('../services/emailService');

// Input validation helper
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

const validatePassword = (password) => {
    // At least 8 characters, 1 uppercase, 1 lowercase, 1 number
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
};

const validateUsername = (username) => {
    // 3-20 characters, alphanumeric and underscores only
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
};

// Generate JWT Token with enhanced security
const generateToken = (user) => {
    return jwt.sign(
        { 
            id: user._id, 
            role: user.role,
            iat: Math.floor(Date.now() / 1000),
            jti: crypto.randomBytes(16).toString('hex')
        },
        process.env.JWT_SECRET,
        { 
            expiresIn: '24h',
            algorithm: 'HS256',
            issuer: 'nydart-advisor',
            audience: 'nydart-users'
        }
    );
};

// Generate Refresh Token with enhanced security
const generateRefreshToken = (user) => {
    return jwt.sign(
        { 
            id: user._id,
            iat: Math.floor(Date.now() / 1000),
            jti: crypto.randomBytes(16).toString('hex')
        },
        process.env.JWT_REFRESH_SECRET,
        { 
            expiresIn: '7d',
            algorithm: 'HS256',
            issuer: 'nydart-advisor',
            audience: 'nydart-users'
        }
    );
};

// Hash password
const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
};

// Register new user
exports.register = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Input validation
        if (!username || !email || !password) {
            return res.status(400).json({
                message: 'Username, email, and password are required'
            });
        }

        if (!validateUsername(username)) {
            return res.status(400).json({
                message: 'Username must be 3-20 characters long and contain only letters, numbers, and underscores'
            });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({
                message: 'Please provide a valid email address'
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({
                message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number'
            });
        }

        // Check if user already exists
        const existingUserByEmail = await DatabaseService.findUserByEmail(email);
        if (existingUserByEmail) {
            return res.status(400).json({
                message: 'User already exists with this email'
            });
        }

        // Check if username already exists
        const existingUserByUsername = await DatabaseService.findUserByUsername(username);
        if (existingUserByUsername) {
            return res.status(400).json({
                message: 'Username already taken'
            });
        }

        // Hash password
        const hashedPassword = await hashPassword(password);

        // Create new user
        const user = await DatabaseService.createUser({
            username,
            email,
            password: hashedPassword
        });

        // Generate tokens
        const token = generateToken(user);
        const refreshToken = generateRefreshToken(user);

        // Update user with refresh token
        await DatabaseService.updateUser(user._id, { refreshToken });

        // Assign free plan in payment service
        try {
            const paymentResponse = await fetch('http://localhost:3004/api/subscriptions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    // Optionally, add an internal API key or service token for security
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    planId: 'free',
                    paymentMethod: 'none'
                })
            });
            if (!paymentResponse.ok) {
                console.error('Payment service returned error for free plan:', paymentResponse.status, paymentResponse.statusText);
            } else {
                const paymentResult = await paymentResponse.json();
                console.log('Free plan assigned in payment service:', paymentResult);
            }
        } catch (paymentError) {
            console.error('Failed to call payment service for free plan:', paymentError);
            // Don't fail registration if payment service call fails
        }

        // Send welcome email to new user
        try {
            const loginLink = `${process.env.CLIENT_URL || 'http://localhost:3000'}/login`;
            const response = await fetch('http://localhost:4003/welcome', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    email, 
                    username,
                    loginLink 
                })
            });

            if (!response.ok) {
                console.error('Notification service returned error for welcome email:', response.status, response.statusText);
            } else {
                const result = await response.json();
                console.log('Welcome email sent successfully:', result);
            }
        } catch (emailError) {
            console.error('Failed to call notification service for welcome email:', emailError);
            // Don't fail the registration if email fails, just log it
        }

        res.status(201).json({
            message: 'User registered successfully',
            token,
            refreshToken,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            message: 'Error registering user',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Login user
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Input validation
        if (!email || !password) {
            return res.status(400).json({
                message: 'Email and password are required'
            });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({
                message: 'Please provide a valid email address'
            });
        }

        // Find user
        const user = await DatabaseService.findUserByEmail(email);
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Check if user is active (with backward compatibility)
        if (user.status && user.status !== 'active') {
            return res.status(401).json({ message: 'Account is not active' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate tokens
        const token = generateToken(user);
        const refreshToken = generateRefreshToken(user);

        // Update user with refresh token and last login
        await DatabaseService.updateUser(user._id, {
            refreshToken,
            lastLogin: new Date()
        });

        res.json({
            token,
            refreshToken,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role || 'user'
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            message: 'Error logging in',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Refresh token
exports.refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({ message: 'Refresh token required' });
        }

        // Verify refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await DatabaseService.findUserById(decoded.id);

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(401).json({ message: 'Invalid refresh token' });
        }

        // Check if user is active (with backward compatibility)
        if (user.status && user.status !== 'active') {
            return res.status(401).json({ message: 'Account is not active' });
        }

        // Generate new tokens
        const newToken = generateToken(user);
        const newRefreshToken = generateRefreshToken(user);

        // Update refresh token
        await DatabaseService.updateUser(user._id, { refreshToken: newRefreshToken });

        res.json({
            token: newToken,
            refreshToken: newRefreshToken
        });
    } catch (error) {
        console.error('Refresh token error:', error);
        res.status(401).json({ message: 'Invalid refresh token' });
    }
};

// Logout
exports.logout = async (req, res) => {
    try {
        // Get user ID from JWT token (req.user should be set by auth middleware)
        const userId = req.user?.id || req.user?._id;
        
        if (!userId) {
            console.error('No user ID found in request for logout');
            return res.status(401).json({
                message: 'User not authenticated',
                error: 'Missing user ID'
            });
        }

        await DatabaseService.updateUser(userId, { refreshToken: null });
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            message: 'Error logging out',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Password reset request
exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || !validateEmail(email)) {
            return res.status(400).json({
                message: 'Please provide a valid email address'
            });
        }

        const user = await DatabaseService.findUserByEmail(email);

        if (!user) {
            // Don't reveal if user exists or not
            return res.json({
                message: 'If an account with that email exists, password reset instructions have been sent'
            });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const passwordResetToken = crypto
            .createHash('sha256')
            .update(resetToken)
            .digest('hex');

        await DatabaseService.updateUser(user._id, {
            passwordResetToken,
            passwordResetExpires: Date.now() + 3600000 // 1 hour
        });

        // Call notification/email service
        try {
            const response = await fetch('http://localhost:4003/notify/email/password-reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, resetToken })
            });

            if (!response.ok) {
                console.error('Notification service returned error:', response.status, response.statusText);
            } else {
                const result = await response.json();
                console.log('Password reset email sent successfully:', result);
            }
        } catch (emailError) {
            console.error('Failed to call notification/email service:', emailError);
            // Don't fail the request if email fails, just log it
        }

        res.json({
            message: 'If an account with that email exists, password reset instructions have been sent'
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            message: 'Error requesting password reset',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Reset password
exports.resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({
                message: 'Token and new password are required'
            });
        }

        if (!validatePassword(newPassword)) {
            return res.status(400).json({
                message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number'
            });
        }

        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const user = await DatabaseService.findUserByResetToken(hashedToken);

        if (!user || user.passwordResetExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        const hashedPassword = await hashPassword(newPassword);
        await DatabaseService.updateUser(user._id, {
            password: hashedPassword,
            passwordResetToken: null,
            passwordResetExpires: null
        });

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            message: 'Error resetting password',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Get current user
exports.getCurrentUser = async (req, res) => {
    try {
        if (!req.user || (!req.user._id && !req.user.id)) {
            console.error('No user ID in request');
            return res.status(401).json({
                message: 'User not authenticated',
                error: 'Missing user ID'
            });
        }

        // Use _id (MongoDB) or id (fallback)
        const userId = req.user._id || req.user.id;
        const user = await DatabaseService.findUserById(userId);
        
        if (!user) {
            console.error('User not found in database:', userId);
            return res.status(404).json({
                message: 'User not found',
                error: 'User does not exist'
            });
        }

        // Create a safe copy of user data with default values for backward compatibility
        const safeUser = {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role || 'user',
            status: user.status || 'active',
            profile: user.profile || {},
            emailVerified: user.emailVerified || false,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt || user.createdAt
        };

        res.json(safeUser);
    } catch (error) {
        console.error('Error in getCurrentUser:', error);
        res.status(500).json({
            message: 'Error fetching user data',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
            details: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
}; 

// Export generateToken for use in routes
exports.generateToken = generateToken;

// Update user's current plan
exports.updateUserPlan = async (req, res) => {
    try {
        const { userId } = req.params;
        const { planId } = req.body;
        if (!planId) {
            return res.status(400).json({ message: 'planId is required' });
        }
        // Update both currentPlan and subscription.type for compatibility
        const user = await DatabaseService.updateUser(userId, {
            currentPlan: planId,
            'subscription.type': planId
        });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User plan updated successfully', user });
    } catch (error) {
        console.error('Error updating user plan:', error);
        res.status(500).json({ message: 'Error updating user plan' });
    }
}; 