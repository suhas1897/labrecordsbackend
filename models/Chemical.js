const mongoose = require('mongoose');

const ChemicalSchema = new mongoose.Schema({
  chemicalId: { type: String, required: true, unique: true },
  chemicalName: { type: String, required: true },
  chemicalType: { type: String, enum: ['Anhydrous', 'Hydrous'], required: true },
  type: { type: String, enum: ['LR', 'AR'], required: true },
  phase: { type: String, enum: ['Solid', 'Liquid', 'Gas'], required: true },
  purity : {type: String },
  quantityAvailable: { type: Number, required: true },
  unit: { type: String, enum: ['g', 'mL', 'L'], required: true },
  make: { type: String },
  dateOfMFG: { type: Date, required: true },
  dateOfExp: { type: Date, required: true },
  purchase: { type: Number },
  purchaseDate: { type: Date },
  invoiceNumber: { type: String },
  isAbsolute: { type: Boolean, default: false },
  isApproximately: { type: Boolean, default: false },
  rack: { type: String, required: true }
});

module.exports = mongoose.model('Chemical', ChemicalSchema);
