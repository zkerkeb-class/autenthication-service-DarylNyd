const express = require('express');
const router = express.Router();
const twoFactorController = require('../controllers/twoFactorController');
const { isAuthenticated } = require('../middleware/auth');

// Two-Factor Authentication routes
router.post('/setup', isAuthenticated, twoFactorController.setupTwoFactor);
router.post('/verify', isAuthenticated, twoFactorController.verifyTwoFactor);
router.post('/disable', isAuthenticated, twoFactorController.disableTwoFactor);
router.get('/status', isAuthenticated, twoFactorController.getTwoFactorStatus);

module.exports = router; 