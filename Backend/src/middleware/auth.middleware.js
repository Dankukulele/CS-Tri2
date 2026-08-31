require('dotenv').config();
const jwt = require('jsonwebtoken');

const {
    logSecurityEvent,
} = require('../utils/securityLogger');

// Verify JWT token from the Authorization header.
const verifyToken = (req, res, next) => {
    const token =
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer ')
            ? req.headers.authorization.split(' ')[1]
            : null;

    // CS-15-T3: Log requests to protected routes without a token.
    if (!token) {
        logSecurityEvent({
            event: 'AUTH_TOKEN_MISSING',
            ip: req.ip,
            method: req.method,
            route: req.originalUrl,
        });

        return res.status(401).json({
            message: 'No token provided',
        });
    }

    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.user = {
            ...decoded,
            role:
                decoded.role ||
                (decoded.admin ? 'admin' : 'user'),
        };

        next();
    } catch (err) {

        // CS-15-T3: Log expired authentication tokens.
        if (err.name === 'TokenExpiredError') {
            logSecurityEvent({
                event: 'AUTH_TOKEN_EXPIRED',
                ip: req.ip,
                method: req.method,
                route: req.originalUrl,
            });

            return res.status(401).json({
                message: 'Token Has Expired',
            });
        }

        // CS-15-T3: Log malformed or invalid authentication tokens.
        logSecurityEvent({
            event: 'AUTH_TOKEN_INVALID',
            ip: req.ip,
            method: req.method,
            route: req.originalUrl,
            details: {
                errorType: err.name,
            },
        });

        return res.status(401).json({
            message: 'Invalid Token',
        });
    }
};

module.exports = verifyToken;
