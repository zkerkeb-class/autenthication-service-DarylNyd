const crypto = require('crypto');

// Security utility functions for detecting suspicious login attempts
class SecurityUtils {
    // Detect if login is from a new device/location
    static async detectSuspiciousLogin(user, req) {
        const suspiciousFactors = [];
        
        // Get device fingerprint
        const deviceInfo = this.getDeviceInfo(req);
        
        // Get location info (basic IP-based)
        const locationInfo = this.getLocationInfo(req);
        
        // Check if this is a new device (simplified check)
        const isNewDevice = !user.lastLoginDevice || 
                           user.lastLoginDevice !== deviceInfo.fingerprint;
        
        // Check if this is a new location (simplified check)
        const isNewLocation = !user.lastLoginLocation || 
                             user.lastLoginLocation !== locationInfo.country;
        
        // Check time-based suspicious activity
        const isUnusualTime = this.isUnusualLoginTime(user);
        
        // Check frequency of logins
        const isFrequentLogin = this.isFrequentLogin(user);
        
        if (isNewDevice) suspiciousFactors.push('new_device');
        if (isNewLocation) suspiciousFactors.push('new_location');
        if (isUnusualTime) suspiciousFactors.push('unusual_time');
        if (isFrequentLogin) suspiciousFactors.push('frequent_login');
        
        return {
            isSuspicious: suspiciousFactors.length > 0,
            factors: suspiciousFactors,
            deviceInfo,
            locationInfo,
            riskLevel: this.calculateRiskLevel(suspiciousFactors)
        };
    }
    
    // Get device information from request
    static getDeviceInfo(req) {
        const userAgent = req.headers['user-agent'] || '';
        const acceptLanguage = req.headers['accept-language'] || '';
        const acceptEncoding = req.headers['accept-encoding'] || '';
        
        // Create a device fingerprint
        const fingerprint = crypto
            .createHash('sha256')
            .update(`${userAgent}${acceptLanguage}${acceptEncoding}`)
            .digest('hex');
        
        // Parse user agent for device info
        const deviceType = this.parseDeviceType(userAgent);
        const browser = this.parseBrowser(userAgent);
        const os = this.parseOS(userAgent);
        
        return {
            fingerprint,
            userAgent,
            deviceType,
            browser,
            os,
            acceptLanguage,
            acceptEncoding
        };
    }
    
    // Get location information from request
    static getLocationInfo(req) {
        // In production, you would use a service like MaxMind or IP2Location
        // For now, we'll use basic IP detection
        const ip = req.ip || 
                   req.connection.remoteAddress || 
                   req.socket.remoteAddress ||
                   req.headers['x-forwarded-for']?.split(',')[0] ||
                   'unknown';
        
        return {
            ip,
            country: 'Unknown', // Would be determined by IP geolocation service
            city: 'Unknown',
            timezone: 'Unknown'
        };
    }
    
    // Check if login time is unusual
    static isUnusualLoginTime(user) {
        if (!user.lastLogin) return false;
        
        const now = new Date();
        const lastLogin = new Date(user.lastLogin);
        const hoursDiff = Math.abs(now - lastLogin) / (1000 * 60 * 60);
        
        // Consider unusual if login is within 1 hour of last login
        // or if it's between 2 AM and 6 AM (unusual hours)
        const isWithinHour = hoursDiff < 1;
        const isUnusualHour = now.getHours() >= 2 && now.getHours() <= 6;
        
        return isWithinHour || isUnusualHour;
    }
    
    // Check if user is logging in too frequently
    static isFrequentLogin(user) {
        if (!user.loginHistory || user.loginHistory.length < 3) return false;
        
        const recentLogins = user.loginHistory
            .filter(login => {
                const loginTime = new Date(login.timestamp);
                const now = new Date();
                const hoursDiff = Math.abs(now - loginTime) / (1000 * 60 * 60);
                return hoursDiff < 24; // Last 24 hours
            });
        
        return recentLogins.length >= 5; // More than 5 logins in 24 hours
    }
    
    // Calculate risk level based on suspicious factors
    static calculateRiskLevel(factors) {
        const factorWeights = {
            'new_device': 2,
            'new_location': 3,
            'unusual_time': 1,
            'frequent_login': 2
        };
        
        const totalRisk = factors.reduce((sum, factor) => {
            return sum + (factorWeights[factor] || 1);
        }, 0);
        
        if (totalRisk >= 5) return 'high';
        if (totalRisk >= 3) return 'medium';
        return 'low';
    }
    
    // Parse device type from user agent
    static parseDeviceType(userAgent) {
        if (userAgent.includes('Mobile')) return 'Mobile';
        if (userAgent.includes('Tablet')) return 'Tablet';
        return 'Desktop';
    }
    
    // Parse browser from user agent
    static parseBrowser(userAgent) {
        if (userAgent.includes('Chrome')) return 'Chrome';
        if (userAgent.includes('Firefox')) return 'Firefox';
        if (userAgent.includes('Safari')) return 'Safari';
        if (userAgent.includes('Edge')) return 'Edge';
        return 'Unknown';
    }
    
    // Parse OS from user agent
    static parseOS(userAgent) {
        if (userAgent.includes('Windows')) return 'Windows';
        if (userAgent.includes('Mac OS')) return 'macOS';
        if (userAgent.includes('Linux')) return 'Linux';
        if (userAgent.includes('Android')) return 'Android';
        if (userAgent.includes('iOS')) return 'iOS';
        return 'Unknown';
    }
    
    // Format device info for display
    static formatDeviceInfo(deviceInfo) {
        return `${deviceInfo.browser} on ${deviceInfo.os} (${deviceInfo.deviceType})`;
    }
    
    // Format location info for display
    static formatLocationInfo(locationInfo) {
        return `${locationInfo.city}, ${locationInfo.country}`;
    }
}

module.exports = SecurityUtils; 