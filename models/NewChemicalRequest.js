const mongoose = require('mongoose');

// Define the NewChemicalRequest schema (if not already defined)
const newChemicalRequestSchema = new mongoose.Schema({
  chemicalName: String,
  userName: String,
  userId: mongoose.Schema.Types.ObjectId,
  date: Date,
  status: { type: String, default: 'pending' },
});
const NewChemicalRequest = mongoose.model('NewChemicalRequest', newChemicalRequestSchema);

module.exports = NewChemicalRequest;
