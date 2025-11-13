// CRITICAL FIX: backend/routes/auth.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const prisma = new PrismaClient();

// Email config
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
}

async function sendOTPEmail(email, otp) {
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'OTP - CberWinX',
        html: `<h2>Your OTP: <strong>${otp}</strong></h2><p>Expires in 5 minutes</p>`
    });
}

// REGISTER
exports.register = async (req, res) => {
    try {
        const { username, email, password, referralCode } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Password 6+ chars' });
        }

        const existing = await prisma.user.findFirst({
            where: { OR: [{ username }, { email }] }
        });

        if (existing) {
            if (!existing.verified) {
                await prisma.user.delete({ where: { id: existing.id } });
            } else {
                return res.status(400).json({ 
                    message: existing.email === email ? 'Email taken' : 'Username taken'
                });
            }
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const otp = generateOTP();
        const otpExpiration = new Date(Date.now() + 5 * 60 * 1000);

        const newUser = await prisma.user.create({
            data: {
                username,
                email,
                password: hashedPassword,
                referralCode: username,
                referredBy: referralCode || null,
                otp,
                otpExpiration,
                verified: false
            }
        });

        if (referralCode) {
            const referrer = await prisma.user.findUnique({ where: { referralCode } });
            if (referrer) {
                await prisma.referral.create({
                    data: {
                        userId: referrer.id,
                        referredUsername: username
                    }
                });
            }
        }

        await sendOTPEmail(email, otp);

        res.status(201).json({ 
            message: 'Check email for OTP',
            email
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// VERIFY OTP - CRITICAL COOKIE FIX
exports.verifyOTP = async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ message: 'Email and OTP required' });
        }

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (user.verified) {
            return res.status(400).json({ message: 'Already verified' });
        }

        if (new Date() > user.otpExpiration) {
            await prisma.user.delete({ where: { id: user.id } });
            return res.status(400).json({ message: 'OTP expired. Register again.' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        await prisma.user.update({
            where: { id: user.id },
            data: {
                verified: true,
                otp: null,
                otpExpiration: null
            }
        });

        // CRITICAL: Generate and set cookie
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/'
        });

        res.json({ 
            message: 'Verified!',
            username: user.username
        });
    } catch (error) {
        console.error('Verify error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// LOGIN - CRITICAL COOKIE FIX
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password required' });
        }

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (!user.verified) {
            await prisma.user.delete({ where: { id: user.id } });
            return res.status(403).json({ message: 'Not verified. Register again.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // CRITICAL: Generate and set cookie
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/'
        });

        res.json({
            message: 'Login successful',
            username: user.username,
            balance: user.balance,
            xp: user.xp
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// LOGOUT
exports.logout = (req, res) => {
    res.clearCookie('auth_token', { path: '/' });
    res.json({ message: 'Logged out' });
};

// RESEND OTP
exports.resendOTP = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (user.verified) {
            return res.status(400).json({ message: 'Already verified' });
        }

        const otp = generateOTP();
        const otpExpiration = new Date(Date.now() + 5 * 60 * 1000);

        await prisma.user.update({
            where: { id: user.id },
            data: { otp, otpExpiration }
        });

        await sendOTPEmail(email, otp);

        res.json({ message: 'OTP resent' });
    } catch (error) {
        console.error('Resend error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

module.exports = exports;