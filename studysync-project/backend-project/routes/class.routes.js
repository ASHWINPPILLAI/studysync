const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth.middleware');
const Class = require('../models/class.model');

const adminAuth = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Access denied' });
  next();
};

// GET all classes (GET /api/classes)
router.get('/', auth, async (req, res) => {
  try {
    const classes = await Class.find();
    res.json(classes);
  } catch (err) { res.status(500).send('Server Error'); }
});

// ADD a new class (POST /api/classes)
router.post('/', [auth, adminAuth], async (req, res) => {
  try {
    const newClass = new Class({ name: req.body.name });
    await newClass.save();
    res.status(201).json(newClass);
  } catch (err) { res.status(500).send('Server Error'); }
});

// DELETE a class (DELETE /api/classes/:id)
router.delete('/:id', [auth, adminAuth], async (req, res) => {
  try {
    await Class.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Class removed' });
  } catch (err) { res.status(500).send('Server Error'); }
});

module.exports = router;