const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const materialSchema = new Schema({
  title: { type: String, required: true },
  description: { type: String },
  fileUrl: { type: String }, 
  subject: { type: String, required: true },
  classId: { type: String, required: true },
  teacherId: { type: String, required: true },
}, { timestamps: true });

const Material = mongoose.model('Material', materialSchema);
module.exports = Material;