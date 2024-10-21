import mongoose from 'mongoose';
import validator from 'validator';
import bcryptjs from 'bcryptjs';

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Please provide a username"],
        trim: true,
        minlength: 3,
        maxlength: 30,
        index: true
    },
    email: {
        type: String,
        required: [true, "Please provide a email"],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, "Please provide a valid email"]
    },
    password: {
        type: String,
        required: [true, "Please provide a password"],
        minlength: 8,
        select: false
    },
    passwordConfirmation: {
        type: String,
        required: [true, "Please confirm a password"],
        validate: {
            validator: function(value) {
                return this.password === value;
            },
            message: "Passwords do not match"
        }
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    otp: {
        type: String,
        default: null
    },
    otpExpires: {
        type: Date,
        default: null
    },
    resetPasswordOTP: {
        type: String,
        default: null
    },
    resetPasswordOTPExpires: {
        type: Date,
        default: null
    },
    role: {
        type: String,
        enum: ['admin', 'student', 'alumnus', 'staff'],
        default: 'student'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
},{
    timestamps: true
});

userSchema.pre('save', async function (next){
    if(!this.isModified('password')) return next();

    this.password = await bcryptjs.hash(this.password, 12);

    this.passwordConfirmation = undefined;

    next();

});

userSchema.methods.correctPassword = async function (password, userPassword) {
    return await bcryptjs.compare(password, userPassword);
};

const User = mongoose.model('User', userSchema);

export default User;