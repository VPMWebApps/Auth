import jwt from 'jsonwebtoken';
import catchAsync from '../utils/catchAsync.js';
import User from '../models/user.model.js';

const isAuthenticatd = catchAsync(async (req, res, next) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return next(new AppError('You are not authenticated! Please login.', 401));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET)

    const currentUser = await User.findById(decoded.id);

    if (!currentUser) {
        return next(new AppError('User no longer exists.', 401));
    }

    req.user = currentUser;
    next();

})

export default isAuthenticatd;
