import dotenv from "dotenv";
import User from "../models/user.model.js";
import AppError from "../utils/appError.js";
import catchAsync from "../utils/catchAsync.js";
import sendEmail from "../utils/email.js";
import generateOTP from "../utils/generateOTP.js";
import jwt from "jsonwebtoken";

dotenv.config();

const secret = process.env.JWT_SECRET;
const ExpiresIn = process.env.JWT_EXPIRES_IN;


const signToken = (id) => {
    return jwt.sign({id}, secret, {
        expiresIn: ExpiresIn
    })
}


const createSendToken = ( user, statusCode, res, message ) => {
    const token = signToken(user._id);

    const cookieOptions = {
        expires: new Date( Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000 ),
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Set secure to true in production
        sameSite: process.env.NODE_ENV === 'production' ? "none" : "Lax"
    };

    res.cookie('token', token, cookieOptions);

    user.password = undefined;
    user.passwordConfirmation = undefined;
    user.otp = undefined;

    res.status(statusCode).json({
        status: 'success',
        message,
        token,
        data: {
            user
        }
    });

}

// Sign up endpoint
const signup = catchAsync( async (req, res, next) => {
    const { username, password, passwordConfirmation, email } = req.body;

    if(!email || !username || !password || !passwordConfirmation) {
        next(new AppError("Please provide all necessary fields", 400));
    }

    const existingUser = await User.findOne({ email });

    if(existingUser) {
        next(new AppError("Email already registered", 400));
    }

    const otp = generateOTP();

    const otpExpires = Date.now() + 24 * 60 * 60 * 1000;

    const newUser = await User.create({
        username,
        email,
        password,
        passwordConfirmation,
        otp,
        otpExpires
    })

    try {
        await sendEmail({
            email: newUser.email,
            subject: "OTP for email verification",
            html: `<h1>Your verification code is: ${otp}</h1>`
        })

        createSendToken(newUser, 200, res, "Registration successful")
    } catch (error) {
        console.log(error.message);
        
        await User.findByIdAndDelete(newUser.id);
        return next(new AppError("There is an error sending email. Please try again later.", 500));
    }

});

// Verification endpoint
const verifyAccount = catchAsync(async (req, res, next) => {
    const { otp } = req.body;

    if(!otp) return next(new AppError("OTP is missing!", 400));

    const user = req.user;

    if(user.otp !== otp) return next(new AppError("Invalid OTP", 400))

    if(Date.now() > user.otpExpires) return next(new AppError("OTP has expires. Please request a new OTP.",400 ))

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save({ validateBeforeSave:false });

    createSendToken(user, 200, res, "Email verification successful")

});

// Resend otp endpoint
const resendOTP = catchAsync(async (req, res, next) => {
    const {email} = req.user;

    if(!email) return next(new AppError("Email is required to resend otp.", 400));

    const user = await User.findOne({email});

    if(!user) return next(new AppError("User not found with this email.", 404));

    if(user.isVerified) return next(new AppError("This account is already verified.", 400))

    const newOtp = generateOTP();
    
    user.otp = newOtp

    user.otpExpires = Date.now() + 24 * 60 * 60 * 1000;

    await user.save({ validateBeforeSave: false });

    try {
        await sendEmail({
            email: user.email,
            subject: "Resend OTP for email verification",
            html: `<h1>Your new verification code is: ${newOtp}</h1>`
        })

        res.status(200).json({
            status: "success",
            message: "OTP has been resent successfully",
        })
    } catch (error) {
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save({ validateBeforeSave: false });
        return next(new AppError("There is an error sending the email! Please try again later.", 500)) 
    }

});

// Login endpoint
const login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if(!email ||!password) return next(new AppError("Please provide email and password", 400));

    const user = await User.findOne({ email }).select('+password');

    if(!user || !(await user.correctPassword(password, user.password))) 
        return next(new AppError("Incorrect email or password", 401));

    createSendToken(user, 200, res, "Login successful");

});

// Logout endpoint
const logout = catchAsync(async (req, res, next) => {
    res.cookie("token", "logged out", {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Set secure to true in production
    });

    res.status(200).json({
        status: "success",
        message: "Logged out successfully",
    });
});

// Forgot Password endpoint
const forgotPassword = catchAsync(async (req, res, next) => {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if(!user) return next(new AppError("User not found.", 404));

    user.resetPasswordOTP = generateOTP();
    user.resetPasswordOTPExpires = Date.now() + 300000;
    
    await user.save({ validateBeforeSave: false });

    try {
        await sendEmail({
            email: user.email,
            subject: "Reset Password OTP",
            html: `<h1>Your reset password OTP is: ${user.resetPasswordOTP}</h1>`
        });

        res.status(200).json({
            status: "success",
            message: "Reset password OTP has been sent to your email.",
        });
    } catch (error) {
        user.resetPasswordOTP=undefined;
        user.resetPasswordOTPExpires=undefined;
        await user.save({ validateBeforeSave: false }); 

        return next(new AppError("There is an error sending the email! Please try again later.", 500));

    }

});

// Reset Password endpoint
const resetPassword = catchAsync(async (req, res, next) => {
    const { email, otp, password, passwordConfirmation } = req.body;

    const user = await User.findOne({ 
        email,
        resetPasswordOTP: otp,
        resetPasswordOTPExpires: {$gt: Date.now()} 
    });

    if(!user) return next(new AppError("No user found.", 400));

    user.password = password;
    user.passwordConfirmation = passwordConfirmation;
    user.resetPasswordOTP = undefined;
    user.resetPasswordOTPExpires = undefined;

    await user.save();

    createSendToken(user, 200, res, "Password reset successfully.");

});


export {
    signup,
    verifyAccount,
    resendOTP,
    login,
    logout,
    forgotPassword,
    resetPassword
}