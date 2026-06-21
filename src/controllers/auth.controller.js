// Import all required modules for authentication flow
import userModel from "../models/user.model.js";
import bcrypt from "bcrypt";
import crypto from 'crypto';
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";
import { sendEmail } from "../services/email.service.js";
import { generateOtp, getOtpHtml } from "../utils/utils.js";
import otpModel from "../models/otp.model.js";

// Create a session and return a new access token for a user
async function createSessionForUser(user, req, res) {
    // Generate refresh token for the user
    const refreshToken = jwt.sign({
        id: user._id
    }, config.JWT_SECRET, {
        expiresIn: "7d"
    });

    // Hash the refresh token before storing it
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    // Save the session information in the database
    const session = await sessionModel.create({
        user: user._id,
        refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers["user-agent"]
    });

    // Generate access token with session reference
    const accessToken = jwt.sign({
        id: user._id,
        sessionId: session._id
    }, config.JWT_SECRET, {
        expiresIn: "15m"
    });

    // Set refresh token cookie on the client
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Return access token for further use
    return accessToken;
}

// Register a new user and send verification email
export async function register(req, res) {
    // Extract registration details from the request body
    const { username, email, password } = req.body || {};

    // Validate that all required fields are present
    if (!username || !email || !password) {
        return res.status(400).json({
            message: "Username, email, and password are required"
        });
    }

    // Check whether the username or email is already in use
    const isAlreadyRegistered = await userModel.findOne({
        $or: [
            { username },
            { email }
        ]
    });

    // Return a conflict response if the user already exists
    if (isAlreadyRegistered) {
        return res.status(409).json({
            message: "Username or email already exists"
        });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create the user record in the database
    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    });

    // Generate a one-time password and email template
    const otp = generateOtp();
    const html = getOtpHtml(otp);

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    await otpModel.create({
        email,
        user: user._id,
        otpHash
    });

    // Send the OTP to the user's email
    await sendEmail(email, "OTP Verification", `Your OTP is ${otp}`, html);





    // Return a success response after registration
    return res.status(201).json({
        message: "User registered successfully",
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    });

}

// Log in a user with email or username credentials
export async function login(req, res) {
    // Read login input from request body
    const { email, usernameOrEmail, password } = req.body;
    const loginIdentifier = email || usernameOrEmail;

    // Validate required login fields
    if (!loginIdentifier || !password) {
        return res.status(400).json({
            message: "Email/username and password are required"
        });
    }

    // Find the user by email or username
    const user = await userModel.findOne({
        $or: [
            { email: loginIdentifier },
            { username: loginIdentifier }
        ]
    });

    // Reject unknown users
    if (!user) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    // Ensure the account has been verified
    if (!user.verified) {
        return res.status(401).json({
            message: "Email not verified"
        });
    }

    // Compare the provided password with the stored hash
    const isPasswordValid = await bcrypt.compare(password, user.password);

    // Reject wrong password
    if (!isPasswordValid) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    // Send successful login response
    res.status(200).json({
        message: "Logged in successfully",
        user: {
            username: user.username,
            email: user.email,
        },
        accessToken,
    });
}



// Get the current authenticated user's profile
export async function getMe(req, res) {
    // Read bearer token from request header
    const token = req.headers.authorization?.split(" ")[1];

    // Reject missing token
    if (!token) {
        return res.status(401).json({
            message: "token not found"
        });
    }

    // Verify token and decode user information
    const decoded = jwt.verify(token, config.JWT_SECRET);

    // Fetch the user from the database
    const user = await userModel.findById(decoded.id);

    // Return user profile details
    res.status(200).json({
        message: "user fetched successfully",
        user: {
            username: user.username,
            email: user.email,
        }
    });
}

// Refresh the access token using the refresh token cookie
export async function refreshToken(req, res) {
    // Read refresh token from cookie
    const refreshToken = req.cookies.refreshToken;

    // Reject missing refresh token
    if (!refreshToken) {
        return res.status(401).json({
            message: "Refresh token not found"
        });
    }

    // Verify the refresh token
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    // Hash the received refresh token for database lookup
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    // Find the matching active session
    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    });

    // Reject invalid or revoked sessions
    if (!session) {
        return res.status(401).json({
            message: "Invalid refresh token"
        });
    }

    // Create a new access token
    const accessToken = jwt.sign({
        id: decoded.id
    }, config.JWT_SECRET, {
        expiresIn: "15m"
    });

    // Create a new refresh token for rotation
    const newRefreshToken = jwt.sign({
        id: decoded.id
    }, config.JWT_SECRET, {
        expiresIn: "7d"
    });

    // Hash and save the new refresh token
    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
    session.refreshTokenHash = newRefreshTokenHash;
    await session.save();

    // Replace the refresh token cookie
    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Return the refreshed access token
    res.status(200).json({
        message: "Access token refreshed successfully",
        accessToken
    });
}

// Log out the current device by revoking the session
export async function logout(req, res) {
    // Read refresh token from cookie
    const refreshToken = req.cookies.refreshToken;

    // Reject missing refresh token
    if (!refreshToken) {
        return res.status(400).json({
            message: "Refresh token not found"
        });
    }

    // Hash the refresh token for lookup
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    // Find the active session
    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    });

    // Reject invalid session
    if (!session) {
        return res.status(400).json({
            message: "Invalid refresh token"
        });
    }

    // Revoke the session
    session.revoked = true;
    await session.save();

    // Clear the cookie from the browser
    res.clearCookie("refreshToken");

    // Send logout success response
    res.status(200).json({
        message: "Logged out successfully"
    });
}

// Log out from all devices for the current user
export async function logoutAll(req, res) {
    // Read refresh token from cookie
    const refreshToken = req.cookies.refreshToken;

    // Reject missing refresh token
    if (!refreshToken) {
        return res.status(400).json({
            message: "Refresh token not found"
        });
    }

    // Verify the refresh token to get the user id
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    // Revoke all active sessions for this user
    await sessionModel.updateMany({
        user: decoded.id,
        revoked: false
    }, {
        revoked: true
    });

    // Clear the cookie
    res.clearCookie("refreshToken");

    // Send success response
    res.status(200).json({
        message: "Logged out from all devices successfully"
    });
}

// Verify the user's email using the OTP sent earlier
export async function verifyEmail(req, res) {
    // Read request data
    const { otp, email } = req.body;

    // Hash the user-provided OTP
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    // Find the matching OTP document
    const otpDoc = await otpModel.findOne({
        email,
        otpHash
    });

    // Reject invalid OTP
    if (!otpDoc) {
        return res.status(400).json({
            message: "Invalid OTP"
        });
    }

    // Mark the user as verified
    const user = await userModel.findByIdAndUpdate(otpDoc.user, {
        verified: true
    });

    // Remove all OTPs for this user
    await otpModel.deleteMany({
        user: otpDoc.user
    });

    // Send success response
    return res.status(200).json({
        message: "Email verified successfully",
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    });
}
