const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const scrapChemicalSchema = new Schema({
  chemicalId: { type: String, required: true },
  chemicalName: { type: String, required: true },
  userName: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, default: 'approved' }
}, {
  timestamps: true // Optional: adds createdAt and updatedAt fields
});

module.exports = mongoose.model('ScrapChemical', scrapChemicalSchema);