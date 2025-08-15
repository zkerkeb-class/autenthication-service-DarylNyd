const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const DatabaseService = require('../services/dbService');

// Setup 2FA - Generate secret and QR code
exports.setupTwoFactor = async (req, res) => {
    try {
        if (!req.user || (!req.user._id && !req.user.id)) {
            return res.status(401).json({
                message: 'User not authenticated',
                error: 'Missing user ID'
            });
        }

        const userId = req.user._id || req.user.id;
        const user = await DatabaseService.findUserById(userId);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate a new secret
        const secret = speakeasy.generateSecret({
            name: `NydArt Advisor (${user.email})`,
            issuer: 'NydArt Advisor',
            length: 32
        });

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // Store the secret temporarily (you might want to store it in the user document)
        // For now, we'll return it and the frontend will send it back for verification
        res.json({
            secret: secret.base32,
            qrCode: qrCodeUrl,
            otpauthUrl: secret.otpauth_url
        });

    } catch (error) {
        console.error('Error setting up 2FA:', error);
        res.status(500).json({
            message: 'Error setting up two-factor authentication',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Verify 2FA setup
exports.verifyTwoFactor = async (req, res) => {
    try {
        if (!req.user || (!req.user._id && !req.user.id)) {
            return res.status(401).json({
                message: 'User not authenticated',
                error: 'Missing user ID'
            });
        }

        const userId = req.user._id || req.user.id;
        const { code, secret } = req.body;

        if (!code || !secret) {
            return res.status(400).json({
                message: 'Verification code and secret are required'
            });
        }

        // Verify the TOTP code
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: code,
            window: 2 // Allow 2 time steps (60 seconds) for clock skew
        });

        if (!verified) {
            return res.status(400).json({
                message: 'Invalid verification code'
            });
        }

        // Enable 2FA for the user
        await DatabaseService.updateUser(userId, {
            twoFactorEnabled: true,
            twoFactorSecret: secret
        });

        res.json({
            message: 'Two-factor authentication enabled successfully'
        });

    } catch (error) {
        console.error('Error verifying 2FA:', error);
        res.status(500).json({
            message: 'Error verifying two-factor authentication',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Disable 2FA
exports.disableTwoFactor = async (req, res) => {
    try {
        if (!req.user || (!req.user._id && !req.user.id)) {
            return res.status(401).json({
                message: 'User not authenticated',
                error: 'Missing user ID'
            });
        }

        const userId = req.user._id || req.user.id;
        const { code } = req.body;

        if (!code) {
            return res.status(400).json({
                message: 'Verification code is required'
            });
        }

        const user = await DatabaseService.findUserById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.twoFactorEnabled || !user.twoFactorSecret) {
            return res.status(400).json({
                message: 'Two-factor authentication is not enabled'
            });
        }

        // Verify the TOTP code
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: code,
            window: 2
        });

        if (!verified) {
            return res.status(400).json({
                message: 'Invalid verification code'
            });
        }

        // Disable 2FA
        await DatabaseService.updateUser(userId, {
            twoFactorEnabled: false,
            twoFactorSecret: null
        });

        res.json({
            message: 'Two-factor authentication disabled successfully'
        });

    } catch (error) {
        console.error('Error disabling 2FA:', error);
        res.status(500).json({
            message: 'Error disabling two-factor authentication',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
};

// Get 2FA status
exports.getTwoFactorStatus = async (req, res) => {
    try {
        if (!req.user || (!req.user._id && !req.user.id)) {
            return res.status(401).json({
                message: 'User not authenticated',
                error: 'Missing user ID'
            });
        }

        const userId = req.user._id || req.user.id;
        const user = await DatabaseService.findUserById(userId);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({
            twoFactorEnabled: user.twoFactorEnabled || false
        });

    } catch (error) {
        console.error('Error getting 2FA status:', error);
        res.status(500).json({
            message: 'Error getting two-factor authentication status',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
}; 