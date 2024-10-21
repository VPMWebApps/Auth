import express from 'express';
import { forgotPassword, login, logout, resendOTP, resetPassword, signup, verifyAccount } from '../controllers/authController.js'
import isAuthenticatd from '../middlewares/isAuthenticated.js';

const router = express.Router();

router.post('/signup', signup)
router.post('/verify', isAuthenticatd, verifyAccount)
router.post('/resend', isAuthenticatd, resendOTP)
router.post('/login', login)
router.post('/logout', logout)
router.post('/forget-password', forgotPassword)
router.post('/reset-password', resetPassword)

export default router;