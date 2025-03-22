const mongoose = require('mongoose');

const scrapRequestSchema = new mongoose.Schema({
  chemicalId: { type: String, required: true },
  chemicalName: { type: String, required: true },
  userName: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: Date, default: Date.now },
  status: { 
    type: String, 
    enum: ['pending', 'admin-approved', 'approved', 'denied'], 
    default: 'pending' 
  },
  scrapPhotoPath: { type: String, required: true },
});

module.exports = mongoose.model('ScrapRequest', scrapRequestSchema);
