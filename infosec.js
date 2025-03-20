const express = require("express");
const cors = require("cors");
const db = require("./database"); // Database connection
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// 🔹 Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ message: "Unauthorized - No token provided" });

    jwt.verify(token.replace("Bearer ", ""), JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Forbidden - Invalid token" });
        req.user = user;
        next();
    });
};

// 🔹 Root route
app.get("/", (req, res) => {
    res.send("Welcome zoz!");
});

// 🔹 Sign up (Register)
app.post("/signup", async (req, res) => {
    const { name, username, password } = req.body;
    console.log("Signup request:", { name, username, password });

    if (!name || !username || !password) {
        return res.status(400).json({ message: "Please fill in all fields" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log("Hashed password:", hashedPassword);

        const [result] = await db.query(
            "INSERT INTO users (name, username, password) VALUES (?, ?, ?)",
            [name, username, hashedPassword]
        );
        console.log("Database result:", result);

        res.status(201).json({ message: "User created successfully!", userId: result.insertId });
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ message: "Error during signup", error: err.message });
    }
});

// 🔹 Login
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    console.log("Login request:", { username, password });

    if (!username || !password) {
        return res.status(400).json({ message: "Please fill in all fields" });
    }

    try {
        const [users] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
        if (users.length === 0) return res.status(401).json({ message: "Username not found" });

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Incorrect password" });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "10m" });
        res.json({ token });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Error during login", error: err.message });
    }
});

// 🔹 Update user info (Needs JWT)
app.put("/users/:id", authenticateToken, async (req, res) => {
    const { name, username } = req.body;
    const userId = req.params.id;
    console.log("Update user request:", { userId, name, username });

    try {
        await db.query("UPDATE users SET name = ?, username = ? WHERE id = ?", [name, username, userId]);
        res.json({ message: "User updated successfully" });
    } catch (err) {
        console.error("Update user error:", err);
        res.status(500).json({ message: "Error updating user", error: err.message });
    }
});

// 🔹 Add product (Needs JWT)
app.post("/products", authenticateToken, async (req, res) => {
    const { pname, description, price, stock } = req.body;
    console.log("Add product request:", { pname, description, price, stock });

    try {
        await db.query(
            "INSERT INTO products (pname, description, price, stock, created_at) VALUES (?, ?, ?, ?, NOW())",
            [pname, description, price, stock]
        );
        res.status(201).json({ message: "Product added successfully!" });
    } catch (err) {
        console.error("Add product error:", err);
        res.status(500).json({ message: "Error adding product", error: err.message });
    }
});

// 🔹 Get all products (Needs JWT)
app.get("/products", authenticateToken, async (req, res) => {
    try {
        const [products] = await db.query("SELECT * FROM products");
        res.json(products);
    } catch (err) {
        console.error("Get products error:", err);
        res.status(500).json({ message: "Error fetching products", error: err.message });
    }
});

// 🔹 Get single product by ID (Needs JWT)
app.get("/products/:pid", authenticateToken, async (req, res) => {
    try {
        const [products] = await db.query("SELECT * FROM products WHERE pid = ?", [req.params.pid]);
        if (products.length === 0) return res.status(404).json({ message: "Product not found" });
        res.json(products[0]);
    } catch (err) {
        console.error("Get product error:", err);
        res.status(500).json({ message: "Error fetching product", error: err.message });
    }
});

// 🔹 Update product (Needs JWT)
app.put("/products/:pid", authenticateToken, async (req, res) => {
    const { pname, description, price, stock } = req.body;
    console.log("Update product request:", { pname, description, price, stock });

    try {
        await db.query("UPDATE products SET pname = ?, description = ?, price = ?, stock = ? WHERE pid = ?", 
            [pname, description, price, stock, req.params.pid]
        );
        res.json({ message: "Product updated successfully" });
    } catch (err) {
        console.error("Update product error:", err);
        res.status(500).json({ message: "Error updating product", error: err.message });
    }
});

// 🔹 Delete product (Needs JWT)
app.delete("/products/:pid", authenticateToken, async (req, res) => {
    try {
        await db.query("DELETE FROM products WHERE pid = ?", [req.params.pid]);
        res.json({ message: "Product deleted successfully" });
    } catch (err) {
        console.error("Delete product error:", err);
        res.status(500).json({ message: "Error deleting product", error: err.message });
    }
});

// 🔹 Start the server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});