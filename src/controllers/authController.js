const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const DatabaseService = require('../services/dbService');

// Generate JWT Token
const generateToken = (user) => {
    return jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
    );
};

// Generate Refresh Token
const generateRefreshToken = (user) => {
    return jwt.sign(
        { id: user._id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
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

        // Check if user already exists
        try {
            await DatabaseService.findUserByEmail(email);
            return res.status(400).json({
                message: 'User already exists with this email'
            });
        } catch (error) {
            // User not found, continue with registration
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
        res.status(500).json({
            message: 'Error registering user',
            error: error.message
        });
    }
};

// Login user
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await DatabaseService.findUserByEmail(email);
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
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
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({
            message: 'Error logging in',
            error: error.message
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
        res.status(401).json({ message: 'Invalid refresh token' });
    }
};

// Logout
exports.logout = async (req, res) => {
    try {
        await DatabaseService.updateUser(req.user.id, { refreshToken: null });
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({
            message: 'Error logging out',
            error: error.message
        });
    }
};

// Password reset request
exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await DatabaseService.findUserByEmail(email);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
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

        // TODO: Send email with reset token
        // This should be implemented with your email service

        res.json({
            message: 'Password reset instructions sent to email',
            resetToken // In production, don't send this in response
        });
    } catch (error) {
        res.status(500).json({
            message: 'Error requesting password reset',
            error: error.message
        });
    }
};

// Reset password
exports.resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;

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
        res.status(500).json({
            message: 'Error resetting password',
            error: error.message
        });
    }
};

// Get current user
exports.getCurrentUser = async (req, res) => {
    try {
        const user = await DatabaseService.findUserById(req.user.id);
        // Remove sensitive data
        delete user.password;
        delete user.refreshToken;
        res.json(user);
    } catch (error) {
        res.status(500).json({
            message: 'Error fetching user data',
            error: error.message
        });
    }
}; 