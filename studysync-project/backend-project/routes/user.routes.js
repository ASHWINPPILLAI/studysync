const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth.middleware');
const User = require('../models/user.model');

// --- GET ALL USERS (GET /api/users) ---
// THIS IS THE CRITICAL FIX:
// We use 'auth' (any logged-in user) instead of 'adminAuth'
// Then, we check the role *inside* the function.
router.get('/', auth, async (req, res) => {
  try {
    let users;

    // IF ADMIN: Send all users
    if (req.user.role === 'admin') {
      users = await User.find().select('-password');
    } 
    // IF TEACHER: Send ONLY students in their assigned classes
    else if (req.user.role === 'teacher') {
      const teacher = await User.findById(req.user.id);
      if (!teacher) return res.status(404).json({ msg: 'Teacher not found' });
      
      // Find students whose 'classId' is in the teacher's 'classIds' array
      users = await User.find({
        role: 'user',
        classId: { $in: teacher.classIds } 
      }).select('-password');
    } 
    // IF STUDENT: Don't send any users
    else {
      return res.status(403).json({ msg: 'Access denied: Insufficient permissions' });
    }
    
    res.json(users);

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// Middleware to check if user is an admin
const adminAuth = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ msg: 'Access denied: Admins only' });
  }
  next();
};

// --- UPDATE USER (PUT /api/users/:id) ---
// This route is still Admin-only
router.put('/:id', [auth, adminAuth], async (req, res) => {
  try {
    const { name, email, role, classId, classIds } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { name, email, role, classId, classIds },
      { new: true } // Return the updated document
    ).select('-password');
    
    if (!updatedUser) return res.status(404).json({ msg: 'User not found' });
    res.json(updatedUser);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// --- DELETE USER (DELETE /api/users/:id) ---
// This route is still Admin-only
router.delete('/:id', [auth, adminAuth], async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ msg: 'User not found' });
    res.json({ msg: 'User removed' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

module.exports = router;