const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const { authenticateUser: protect, authorizeRole } = require("../middleware/authMiddleware");
require("dotenv").config();

console.log('Loading auth routes...');

const router = express.Router();

// Move /me route to be registered first
router.get("/me", async (req, res) => {
    console.log('ME route hit - before auth check');
    try {
        if (!req.cookies.refreshToken) {
            return res.status(401).json({ message: "Not authorized, no token" });
        }

        const token = req.cookies.refreshToken;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const user = await User.findByPk(decoded.id, {
            attributes: { exclude: ["password"] },
        });
        
        console.log('User found:', user ? 'yes' : 'no');
        if (!user) return res.status(404).json({ message: "User not found" });

        res.json(user);
    } catch (err) {
        console.error("❌ Fetch User Error:", err);
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: "Invalid token" });
        }
        res.status(500).json({ message: "Internal server error" });
    }
});

// Generate JWT Token
const generateToken = (user) => {
    return jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );
};

// ✅ REGISTER A NEW USER
router.post("/register", async (req, res) => {
    try {
        const { name, email, password, role, termsAccepted } = req.body;

        if (!termsAccepted) {
            return res.status(400).json({ 
                message: "You must accept the terms and conditions to register" 
            });
        }

        // Check if user already exists
        let user = await User.findOne({ where: { email } });
        if (user) return res.status(400).json({ message: "User already exists" });

        // Validate role
        const validRoles = ['Student', 'Instructor', 'Admin'];
        if (!validRoles.includes(role)) {
            return res.status(400).json({ message: "Invalid role selected" });
        }

        // Hash password and create user
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = await User.create({
            name,
            email,
            password: hashedPassword,
            role,
            termsAccepted: true,
            termsAcceptedDate: new Date()
        });

        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("❌ Registration Error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ LOGIN USER & RETURN TOKEN
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(400).json({ message: "Invalid credentials" });

        // Validate Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

        // Generate JWT Token
        const token = generateToken(user);

        // Change cookie name to refreshToken
        res.cookie("refreshToken", token, {
            httpOnly: true,
            secure: false,   
            sameSite: "lax", 
            maxAge: 3600000, 
        });

        res.json({ message: "Login successful", role: user.role });
    } catch (err) {
        console.error("❌ Login Error:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ LOGOUT USER (Clear JWT Cookie)
router.post("/logout", (req, res) => {
    res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
    });
    res.json({ message: "Logged out successfully" });
});

// ✅ Instructor-Only Access Middleware
const requireInstructor = (req, res, next) => {
    if (req.user.role !== "Instructor") {
        return res.status(403).json({ message: "Access Denied. Instructors Only." });
    }
    next();
};

// ✅ Instructor-Only Route
router.get("/instructor-only", protect, requireInstructor, (req, res) => {
    res.json({ message: "Welcome, Instructor!" });
});

console.log('Auth routes loaded, routes:', router.stack.map(layer => {
    return {
        path: layer.route?.path,
        method: layer.route?.stack[0].method
    };
}));

module.exports = router;
