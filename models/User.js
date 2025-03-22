const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user', 'superadmin'], required: true },
    salutation: {type: String, enum: ['Dr', 'Ms', 'Mr', 'Mrs'], required: true},
    designation: {type: String, enum: ['Principal_Investigator','Co_Principal_Investigator','Post_Doctoral_Fellow','Research Associate','Senior_Research_Fellow', 'Junior_Research_Fellow', 'Project Associate', 'Project Assistant','Research Scholar', 'Student Research Intern', 'Other'], required: true},
    department: {type: String, required: true},
    contactNumber: { type: String, required: true },
    
    joiningDate: { type: Date, required: true },
    status: { type: String, enum: ['pending', 'approved', 'removed'], default: 'pending' }

  });

module.exports = mongoose.model('User', UserSchema);
