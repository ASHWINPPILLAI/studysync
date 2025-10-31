const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth.middleware');
const Mark = require('../models/mark.model');
const User = require('../models/user.model');

// Middleware for teachers
const teacherAuth = (req, res, next) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ msg: 'Access denied: Teachers only' });
  next();
};

// GET all marks (for admins or specific users)
// GET /api/marks
router.get('/', auth, async (req, res) => {
  try {
    let marks;
    if (req.user.role === 'admin') {
      marks = await Mark.find();
    } else if (req.user.role === 'teacher') {
      marks = await Mark.find({ teacherId: req.user.id });
    } else { // 'user' (student)
      marks = await Mark.find({ studentId: req.user.id });
    }
    res.json(marks);
  } catch (err) { res.status(500).send('Server Error'); }
});

// ADD new marks (POST /api/marks)
router.post('/', [auth, teacherAuth], async (req, res) => {
  try {
    const { studentId, subject, marks, classId } = req.body;
    const student = await User.findById(studentId);
    if (!student) return res.status(404).json({ msg: 'Student not found' });
    
    const newMark = new Mark({
      studentId,
      studentName: student.name,
      subject,
      marks,
      classId,
      teacherId: req.user.id
    });
    
    await newMark.save();
    res.status(201).json(newMark);
  } catch (err) { res.status(500).send('Server Error'); }
});

// UPDATE A MARK (PUT /api/marks/:id)
router.put('/:id', auth, async (req, res) => {
  try {
    const { marks } = req.body;
    if (!marks) {
      return res.status(400).json({ msg: 'Marks value is required' });
    }

    let mark = await Mark.findById(req.params.id);
    if (!mark) return res.status(404).json({ msg: 'Mark not found' });

    // Check authorization (Admin or the Teacher who created it)
    if (req.user.role !== 'admin' && mark.teacherId.toString() !== req.user.id) {
      return res.status(403).json({ msg: 'Not authorized' });
    }

    mark.marks = marks;
    await mark.save();
    res.json(mark);
  
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});


// DELETE marks (DELETE /api/marks/:id)
router.delete('/:id', auth, async (req, res) => {
  try {
    const mark = await Mark.findById(req.params.id);
    if (!mark) return res.status(404).json({ msg: 'Mark not found' });

    // Only Admin or the Teacher who created it can delete
    if (req.user.role !== 'admin' && mark.teacherId.toString() !== req.user.id) {
      return res.status(403).json({ msg: 'Not authorized' });
    }
    
    await Mark.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Mark removed' });
  } catch (err) { res.status(500).send('Server Error'); }
});

module.exports = router;