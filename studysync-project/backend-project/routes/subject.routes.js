const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth.middleware');
const Subject = require('../models/subject.model');

const adminAuth = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Access denied' });
  next();
};

// GET all subjects (GET /api/subjects)
router.get('/', auth, async (req, res) => {
  try {
    const subjects = await Subject.find();
    res.json(subjects);
  } catch (err) { res.status(500).send('Server Error'); }
});

// ADD a new subject (POST /api/subjects)
router.post('/', [auth, adminAuth], async (req, res) => {
  try {
    const newSubject = new Subject({ name: req.body.name });
    await newSubject.save();
    res.status(201).json(newSubject);
  } catch (err) { res.status(500).send('Server Error'); }
});

// DELETE a subject (DELETE /api/subjects/:id)
router.delete('/:id', [auth, adminAuth], async (req, res) => {
  try {
    await Subject.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Subject removed' });
  } catch (err) { res.status(500).send('Server Error'); }
});

module.exports = router;