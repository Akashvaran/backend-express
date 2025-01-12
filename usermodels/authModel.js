import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Name is required"],
    maxlength: [20, "Name must be at most 20 characters"],
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
  },
  mobile: {
    type: String,
    required: [true, "Mobile number is required"],
  },
  password: {
    type: String,
    required: [true, "Password is required"],
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  }
}, {
  timestamps: true,
});

const userModel = mongoose.model('User', userSchema);

export { userModel };