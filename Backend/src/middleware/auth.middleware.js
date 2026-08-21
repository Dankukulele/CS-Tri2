
require('dotenv').config();
const jwt = require('jsonwebtoken');
const { logSecurityEvent } = require('../utils/securityLogger');

// new Changed the logic for extracting the token from the Authorization header to explicitly check if it starts with 'Bearer '
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
        ? req.headers.authorization.split(' ')[1] // Extract the token part after "Bearer"
        : null; // If no token is found, set it to null

    if (!token) {
            logSecurityEvent({
                event: 'INVALID_TOKEN_USAGE',
                ip: req.ip,
                method:req.method,
                route: req.originalUrl,
                details: ['No authentication token provided'],
            });

        return res.status(401).json({message: "No token provided"});
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = {
            ...decoded,
            role: decoded.role || (decoded.admin ? 'admin' : 'user')
        };

        next();
    } catch (err) {

        logSecurityEvent({
            event: 'INVALID_TOKEN_USAGE',
            ip: req.ip,
            method:req.method,
            route: req.originalUrl,
            details: [
                err.name === 'TokenExpiredError'
                    ? 'Expired authentication token.'
                    : 'Invalid authentication token.'
            ],
        });

        if (err.name === "TokenExpiredError") {
            return res.status(401).json({message: "Token Has Expired"});
        }
        return res.status(401).json({ message: "Invalid Token"});
    }

};

module.exports = verifyToken;
