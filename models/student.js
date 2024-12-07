const mongoose = require('mongoose');

// Define Student schema
const studentSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  studentID: { type: String, required: true, unique: true },
  face: { data: Buffer, contentType: String } // Store face image as binary data
});

// Export the model
module.exports = mongoose.model('Student', studentSchema);