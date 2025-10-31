const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth.middleware');
const Material = require('../models/material.model');
const User = require('../models/user.model'); 

// Middleware for teachers
const teacherAuth = (req, res, next) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ msg: 'Access denied: Teachers only' });
  next();
};

// GET all materials (for admins or specific classes)
// GET /api/materials
router.get('/', auth, async (req, res) => {
  try {
    let materials;
    if (req.user.role === 'admin') {
      materials = await Material.find();
    } else if (req.user.role === 'teacher') {
      materials = await Material.find({ teacherId: req.user.id });
    } else { // 'user' (student)
      const student = await User.findById(req.user.id);
      if (!student) return res.status(404).json({ msg: 'Student not found' });
      materials = await Material.find({ classId: student.classId });
    }
    res.json(materials);
  } catch (err) { res.status(500).send('Server Error'); }
});

// ADD new material (POST /api/materials)
router.post('/', [auth, teacherAuth], async (req, res) => {
  try {
    const { title, description, fileUrl, subject, classId } = req.body;

    // Validation: Title, Subject, and Class are required. FileUrl is optional.
    if (!title || !subject || !classId) {
      return res.status(4DE).json({ msg: 'Title, Subject, and Class are required.' });
    }
    
    const newMaterial = new Material({
      title,
      description,
      fileUrl,
      subject,
      classId,
      teacherId: req.user.id
    });
    
    await newMaterial.save();
    res.status(201).json(newMaterial);
  } catch (err) { res.status(500).send('Server Error'); }
});

// DELETE material (DELETE /api/materials/:id)
router.delete('/:id', auth, async (req, res) => {
  try {
    const material = await Material.findById(req.params.id);
    if (!material) return res.status(404).json({ msg: 'Material not found' });

    // Only Admin or the Teacher who created it can delete
    if (req.user.role !== 'admin' && material.teacherId.toString() !== req.user.id) {
      return res.status(403).json({ msg: 'Not authorized' });
    }
    
    await Material.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Material removed' });
  } catch (err) { res.status(500).send('Server Error'); }
});

module.exports = router;