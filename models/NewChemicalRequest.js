const mongoose = require('mongoose');

const newChemicalRequestSchema = new mongoose.Schema({
  chemicalName: { type: String, required: true },
  userName: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'denied'], default: 'approved' }
});

module.exports = mongoose.model('NewChemicalRequest', newChemicalRequestSchema);