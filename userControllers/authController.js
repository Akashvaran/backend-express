import { userModel } from "../usermodels/authModel.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import sendEmail from "./nodeMailer.js";

const generateToken = (id, name, role) => {
    return jwt.sign({ id, name, role }, process.env.JWT_SECRET, { expiresIn: "1h" });
};

// 1. User Sign Up
export const signup = async (req, res, next) => {
    const { name, email, mobile, password } = req.body;
    try {
    
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new userModel({ name, email, mobile, password: hashedPassword, role: 'user' });

        await newUser.save();

        const token = generateToken(newUser._id, newUser.name, newUser.role);
        res.cookie("jwt", token, { maxAge: 3600000, httpOnly: true });

        res.status(201).json({
            message: "User created successfully",
            user: { id: newUser._id, name: newUser.name, role: newUser.role }
        });
    } catch (err) {
        next(err);
    }
};

// 2. User Login
export const login = async (req, res, next) => {
    const { email, password } = req.body;
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const token = generateToken(user._id, user.name, user.role);
        res.cookie("jwt", token, { maxAge: 3600000, httpOnly: true });

        res.status(200).json({
            message: "Login successful",
            user: { id: user._id, name: user.name, role: user.role }
        });
    } catch (err) {
        next(err);
    }
};
//3. User forgetPassword
export const forgetPassword = async (req, res, next) => {    
    const { email } = req.body;
    try {
        const user = await userModel.findOne({ email });
        
        if (!user) {
            return res.status(404).json({ status: false, message: "User not found" });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "10m" });
        const encodedToken = encodeURIComponent(token);
        const resetLink = `http://localhost:5173/reset/${encodedToken}`;

        const htmlContent = `
            <h1>Reset Your Password</h1>
            <p>Click the link below to reset your password:</p>
            <a href="${resetLink}">${resetLink}</a>
            <p>This link will expire in 15 minutes.</p>
        `;

        await sendEmail(email, "Password Reset Request", htmlContent);

        res.status(200).json({ status: true, message: "Reset link sent to your email" });
    } catch (err) {
        console.error("Error during forget password:", err);
        next(err);
    }
};
//4.User ResetPassword
export const resetPassword = async (req, res, next) => {
       
    const { token } = req.params;
    const { password } = req.body;

    try {
        const decodedToken = jwt.verify(decodeURIComponent(token), process.env.JWT_SECRET);
        const userId = decodedToken.id;

        const hashedPassword = await bcrypt.hash(password, 10);

        const updatedUser = await userModel.findByIdAndUpdate(
            userId,
            { password: hashedPassword },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ status: true, message: "Password updated successfully" });
    } catch (err) {
        console.error("Error during reset password:", err);
        next(err);
    }
};

// 5. Get All Users
export const Verify = async (req, res) => {
    try {
        const token = req.cookies.jwt;
        if (!token) {
            return res.status(401).json({ status: false, msg: "Not authorized" });
        }

        const decodedData = jwt.verify(token, process.env.JWT_SECRET);
        res.status(200).json({ status: true, user: decodedData });
    } catch (err) {
        res.status(401).json({ status: false, msg: "Invalid token" });
        next(err)
    }
};
//6.User logout
export const logout = async (req, res, next) => {
    try {
        res.cookie("jwt", "", { httpOnly: true, maxAge: 0 });
        res.status(200).json({ message: 'User logged out successfully' });
    } catch (err) {
        next(err);
    }
};