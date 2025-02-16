const jwt = require("jsonwebtoken");
const User = require("../models/User");
require("dotenv").config();

// Middleware to verify JWT Token
const authenticateUser = async (req, res, next) => {
    try {
        console.log('Auth Middleware - Cookies:', req.cookies);
        console.log('Auth Middleware - Headers:', req.headers);
        
        let token = req.cookies.refreshToken || req.cookies.token || req.header("Authorization")?.replace("Bearer ", ""); 
        console.log('Auth Middleware - Token:', token);
        
        if (!token) {
            return res.status(401).json({ message: "Not authorized, no token provided" });
        }

        // Verify JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findByPk(decoded.id, {
            attributes: { exclude: ["password"] },
        });

        if (!req.user) {
            return res.status(401).json({ message: "User not found" });
        }

        next();
    } catch (err) {
        console.error("JWT Auth Error:", err);
        return res.status(401).json({ message: "Not authorized, invalid token" });
    }
};

// Middleware to check user roles
const authorizeRole = (roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
        return res.status(403).json({ message: "Access denied. Insufficient permissions." });
    }
    next();
};

module.exports = { authenticateUser, authorizeRole };
