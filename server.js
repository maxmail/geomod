const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const listEndpoints = require('express-list-endpoints');

const app = express();

app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["set-cookie"]
}));

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Add this before your routes
app.get('/test', (req, res) => {
    res.json({ message: 'Server is running' });
});

// Before loading routes
console.log('Loading routes...');

// Load Routes
const authRoutes = require("./routes/auth");
app.use("/api/auth", authRoutes);

// After loading routes
console.log('Routes loaded. Available auth routes:', authRoutes.stack.map(r => r.route?.path).filter(Boolean));

// Add route debugging with more detail
app.use((req, res, next) => {
    console.log('Request:', {
        method: req.method,
        path: req.path,
        cookies: req.cookies,
        headers: req.headers
    });
    next();
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ message: "Internal server error" });
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log('Registered Routes:');
    console.log(listEndpoints(app));
});
