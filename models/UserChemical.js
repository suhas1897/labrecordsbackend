const mongoose = require('mongoose');
const UserChemicalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    chemicalId: { type: String, required: true },
    chemicalName: { type: String, required: true },
    gramsUsed: { type: Number, required: true },
    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('UserChemical', UserChemicalSchema);