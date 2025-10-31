const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: {
    type: String,
    enum: ['user', 'teacher', 'admin'],
    default: 'user',
  },
  classId: { type: String, default: null }, // For 'user' (student) role
  classIds: { type: [String], default: [] } // For 'teacher' role
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
module.exports = User;