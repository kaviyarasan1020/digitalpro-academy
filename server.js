
const express = require("express");
const cors = require("cors");
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname, { index: false }));
app.get("/admin-login.html", (req, res) => {
    res.sendFile(__dirname + "/admin-login.html");
});

app.get("/admin.html", (req, res) => {
    res.sendFile(__dirname + "/admin.html");
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log("MongoDB Connected Successfully!");
    })
    .catch((error) => {
        console.log("MongoDB Connection Error:", error.message);
    });

// Student Schema
const studentSchema = new mongoose.Schema({
    studentName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        lowercase: true
    },
    mobile: {
        type: String,
        required: true,
        unique: true
    },
    course: {
        type: String,
        required: true
    },
    qualification: {
        type: String,
        required: true
    },
    message: {
        type: String,
        default: ""
    }
}, { timestamps: true });

// Student Model
const Student = mongoose.model("Student", studentSchema);

// Home API
app.get("/", (req, res) => {
    res.send("DigitalPro Academy Backend is Running!");
});

// Test API
app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        message: "DigitalPro Academy API is working!"
    });
});

// Admin Login API
app.post("/api/admin/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password required"
            });
        }

        if (email !== process.env.ADMIN_EMAIL) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            process.env.ADMIN_PASSWORD_HASH
        );

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        const token = jwt.sign(
            { email: email, role: "admin" },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
        );

        res.json({
            success: true,
            message: "Admin login successful",
            token: token
        });

    } catch (error) {
        console.log("Admin Login Error:", error.message);

        res.status(500).json({
            success: false,
            message: "Login failed"
        });
    }
});

// Admin Authentication Middleware
function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Access denied. Please login."
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded.role !== "admin") {
            return res.status(403).json({
                success: false,
                message: "Admin access only"
            });
        }

        req.admin = decoded;
        next();

    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired token"
        });
    }
}

// Get All Students API (Admin Only)
app.get("/api/students", verifyAdmin, async (req, res) => {
    try {
        const students = await Student.find().sort({
            createdAt: -1
        });

        res.json({
            success: true,
            total: students.length,
            students: students
        });

    } catch (error) {
        console.log(error.message);

        res.status(500).json({
            success: false,
            message: "Unable to fetch students"
        });
    }
});

// Student Admission API
app.post("/api/admission", async (req, res) => {
    try {
        const {
            studentName,
            email,
            mobile,
            course,
            qualification,
            message
        } = req.body;

        if (!studentName || !email || !mobile ||
            !course || !qualification) {
            return res.status(400).json({
                success: false,
                message: "Please fill all required fields"
            });
        }

        const student = new Student({
            studentName,
            email,
            mobile,
            course,
            qualification,
            message
        });

        await student.save();

        res.status(201).json({
            success: true,
            message: "Admission submitted successfully!"
        });

    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: "This mobile number is already registered!"
            });
        }

        console.log(error.message);

        res.status(500).json({
            success: false,
            message: "Something went wrong"
        });
    }
});

// Server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
