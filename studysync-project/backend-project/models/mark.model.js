const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const markSchema = new Schema({
  studentId: { type: String, required: true },
  studentName: { type: String, required: true },
  subject: { type: String, required: true },
  marks: { type: String, required: true },
  classId: { type: String, required: true },
  teacherId: { type: String, required: true },
}, { timestamps: true });

const Mark = mongoose.model('Mark', markSchema);
module.exports = Mark;