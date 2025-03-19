const mongoose = require('mongoose');

const ChemicalSchema = new mongoose.Schema({
  chemicalId: { type: String, required: true, unique: true },
  chemicalName: { type: String, required: true },
  chemicalType: { type: String, required: true },
  type: { type: String, required: true },
  gramsAvailable: { type: Number, required: true },
  make: { type: String, required: true },
  dateOfMFG: { type: Date, required: true },
  dateOfExp: { type: Date, required: true },
  purchaseDate: { type: Date },
  purchase: { type: Number, required: false }, // Add purchase, optional for existing data
});

module.exports = mongoose.model('Chemical', ChemicalSchema);