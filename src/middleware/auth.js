const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DatabaseService = require('../services/dbService');

// JWT options
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
};

if (!process.env.JWT_SECRET) {
    console.error('JWT_SECRET is not set in environment variables');
    process.exit(1);
}

// JWT Strategy
passport.use(new JwtStrategy(jwtOptions, async (jwt_payload, done) => {
    try {
        const user = await DatabaseService.findUserById(jwt_payload.id);
        if (user) {
            return done(null, user);
        }
        return done(null, false);
    } catch (error) {
        console.error('Error in JWT strategy:', error);
        return done(error, false);
    }
}));

// Google Strategy (only if credentials are provided)
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback"
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            // Validate profile data
            if (!profile || !profile.id) {
                console.error('Invalid Google profile data');
                return done(new Error('Invalid profile data from Google'), false);
            }

            if (!profile.emails || !profile.emails[0] || !profile.emails[0].value) {
                console.error('No email found in Google profile');
                return done(new Error('Email is required for registration'), false);
            }

            const email = profile.emails[0].value;
            const socialId = profile.id;

            // First, try to find user by social ID
            let user = await DatabaseService.findUserBySocialId('google', socialId);

            if (!user) {
                // User not found by social ID, check if user exists with same email
                try {
                    user = await DatabaseService.findUserByEmail(email);
                    
                    if (user) {
                        // User exists but doesn't have Google social login
                        // Update the user to add Google social login
                        const updateData = {
                            socialLogin: {
                                provider: 'google',
                                socialId: socialId,
                                accessToken: accessToken
                            },
                            emailVerified: true
                        };
                        
                        // Update profile if not already set
                        if (!user.profile || !user.profile.name) {
                            updateData.profile = {
                                name: profile.displayName || 'Google User',
                                avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null
                            };
                        }
                        
                        user = await DatabaseService.updateUser(user._id, updateData);
                        console.log('Updated existing user with Google social login:', user.email);
                    } else {
                        // Create new user
                        const username = profile.displayName 
                            ? profile.displayName.replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase()
                            : `user_${socialId}`;

                        user = await DatabaseService.createUser({
                            username,
                            email: email,
                            socialLogin: {
                                provider: 'google',
                                socialId: socialId,
                                accessToken: accessToken
                            },
                            profile: {
                                name: profile.displayName || 'Google User',
                                avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null
                            },
                            emailVerified: true
                        });
                        console.log('Created new user with Google social login:', user.email);
                    }
                } catch (createError) {
                    console.error('Error creating/updating user for Google OAuth:', createError);
                    if (createError.message === 'User already exists') {
                        // Try to find the user again in case of race condition
                        user = await DatabaseService.findUserByEmail(email);
                        if (!user) {
                            return done(new Error('Failed to create or find user account'), false);
                        }
                    } else {
                        return done(createError, false);
                    }
                }
            }

            return done(null, user);
        } catch (error) {
            console.error('Error in Google strategy:', error);
            return done(error, false);
        }
    }));
} else {
    console.warn('Google OAuth credentials not provided - Google login disabled');
}

// Serialize user for the session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await DatabaseService.findUserById(id);
        done(null, user);
    } catch (error) {
        console.error('Error deserializing user:', error);
        done(error, null);
    }
});

// Middleware to check if user is authenticated
const isAuthenticated = passport.authenticate('jwt', { session: false });

// Middleware to check user role
const checkRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Forbidden - Insufficient permissions' });
        }

        next();
    };
};

module.exports = {
    passport,
    isAuthenticated,
    checkRole
}; 