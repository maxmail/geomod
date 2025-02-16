console.log("✅ Auth Routes Loaded");

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const User = require('../models/User');
const { authenticateUser, authorizeRole } = require('../middleware/authMiddleware');
require('dotenv').config();

const router = express.Router();

// ✅ Refresh Token Model
const RefreshToken = sequelize.define("refresh_tokens", {
  id: {
    type: DataTypes.UUID,
    primaryKey: true,
    defaultValue: Sequelize.UUIDV4,
  },
  user_id: {
    type: DataTypes.UUID,
    references: {
      model: 'Users',
      key: "id",
    },
    onDelete: "CASCADE",
  },
  token: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
}, {
  timestamps: true, // ✅ Ensures createdAt and updatedAt columns exist
  underscored: true, // ✅ Matches PostgreSQL snake_case naming conventions
});

// 🔹 Utility function to remove sensitive data from user object
const sanitizeUser = (user) => {
  const { password, ...userWithoutPassword } = user.dataValues;
  return userWithoutPassword;
};

// ✅ Register a new user
router.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const normalizedEmail = email.toLowerCase();

    const existingUser = await User.findOne({ where: { email: normalizedEmail } });
    if (existingUser) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = await User.create({
      name,
      email: normalizedEmail,
      password: hashedPassword,
      role,
      trialEndDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) 
    });

    res.status(201).json({ message: 'User registered successfully', user: sanitizeUser(newUser) });
  } catch (error) {
    console.error("❌ Registration Error:", error.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// ✅ Login user
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const normalizedEmail = email.toLowerCase();
    console.log("🔍 Looking up user:", normalizedEmail);

    const user = await User.findOne({ where: { email: normalizedEmail } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

    await RefreshToken.create({ user_id: user.id, token: refreshToken });

    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict' });
    res.json({ message: 'Login successful', token, user: sanitizeUser(user) });
  } catch (error) {
    console.error("❌ Server Error:", error.message);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ✅ Refresh Token Route
router.post('/refresh-token', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(403).json({ error: "Access denied. No refresh token provided." });
  }
  try {
    const existingToken = await RefreshToken.findOne({ where: { token: refreshToken } });
    if (!existingToken) {
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const newToken = jwt.sign({ id: decoded.id, role: decoded.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token: newToken });
  } catch (error) {
    console.error("❌ Refresh Token Error:", error.message);
    res.status(401).json({ error: "Invalid or expired refresh token" });
  }
});

// ✅ Logout user
router.post('/logout', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) {
    await RefreshToken.destroy({ where: { token: refreshToken } });
  }
  res.clearCookie("refreshToken");
  res.status(200).json({ message: "Logout successful" });
});

module.exports = router;
