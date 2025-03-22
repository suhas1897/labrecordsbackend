const mongoose = require('mongoose');

const userChemicalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    chemicalId: { type: String, required: true },
    chemicalName: { type: String, required: true },
    quantityUsed: { type: Number, required: true }, // Renamed from gramsUsed
    unit: { type: String, required: true }, // Add unit field
    date: { type: Date, default: Date.now },
    name: { type: String, required: true }
});

module.exports = mongoose.model('UserChemical', userChemicalSchema);
