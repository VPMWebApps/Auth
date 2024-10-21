import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import globalErrorHandler from './controllers/errorController.js';
import AppError from './utils/appError.js';
import userRoutes from './routes/userRouters.js';

const app = express();

app.use(cookieParser());
app.use(cors({
    origin: [process.env.CLIENT_URL,
        'http://localhost:5173',
    ],
    credentials: true,
}));
app.use(express.json({ limit: "10kb" }));

// User api routes
app.use('/api/v1/users', userRoutes)

app.all("*", (err, req, res) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

// module.exports = {app};
export default app;