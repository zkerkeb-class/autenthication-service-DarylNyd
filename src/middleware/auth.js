const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const DatabaseService = require('../services/dbService');

// Debug logging
console.log('Initializing authentication middleware with JWT_SECRET:', process.env.JWT_SECRET ? 'Set' : 'Not Set');

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
            let user = await DatabaseService.findUserBySocialId('google', profile.id);

            if (!user) {
                user = await DatabaseService.createUser({
                    username: `google_${profile.id}`,
                    email: profile.emails[0].value,
                    socialLogin: {
                        provider: 'google',
                        socialId: profile.id,
                        accessToken
                    },
                    profile: {
                        name: profile.displayName,
                        avatar: profile.photos[0].value
                    },
                    emailVerified: true
                });
            }

            return done(null, user);
        } catch (error) {
            console.error('Error in Google strategy:', error);
            return done(error, false);
        }
    }));
}

// Facebook Strategy (only if credentials are provided)
if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
    passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "/auth/facebook/callback",
        profileFields: ['id', 'emails', 'name', 'picture']
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await DatabaseService.findUserBySocialId('facebook', profile.id);

            if (!user) {
                user = await DatabaseService.createUser({
                    username: `fb_${profile.id}`,
                    email: profile.emails[0].value,
                    socialLogin: {
                        provider: 'facebook',
                        socialId: profile.id,
                        accessToken
                    },
                    profile: {
                        name: `${profile.name.givenName} ${profile.name.familyName}`,
                        avatar: profile.photos[0].value
                    },
                    emailVerified: true
                });
            }

            return done(null, user);
        } catch (error) {
            console.error('Error in Facebook strategy:', error);
            return done(error, false);
        }
    }));
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