import mongoose from 'mongoose';
import dotenv from 'dotenv';
import app from './app.js';

dotenv.config({
    path: "./.env"
});

const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;

// connect application to database

mongoose.connect(MONGO_URI).then( () => {
    console.log('Connected to MongoDB...');
}).catch(err => {
    console.log(err.message)
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
})