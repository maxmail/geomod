router.post("/login", async (req, res) => {
    try {
        // ... existing code ...
    } catch (err) {
        console.error("❌ Login Error:", err);
        res.status(500).json({ 
            message: "Internal server error",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined 
        });
    }
});

router.post("/refresh-token", protect, async (req, res) => {
    try {
        const token = generateToken(req.user);
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 3600000,
        });
        res.json({ message: "Token refreshed" });
    } catch (err) {
        res.status(500).json({ message: "Token refresh failed" });
    }
});