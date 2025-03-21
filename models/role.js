const User = require('./User'); // Adjust path to your User model

// Fetch admin and super admin emails from MongoDB
const getAdminEmails = async () => {
  try {
    const admins = await User.find({ role: 'admin', status: 'approve' }).select('email');
    const superAdmins = await User.find({ role: 'superadmin', status: 'approve' }).select('email');

    const adminEmails = admins.map(admin => admin.email);
    const superAdminEmails = superAdmins.map(admin => admin.email);
    // console.log(adminEmails, superAdminEmails);

    return { adminEmails, superAdminEmails };
  } catch (error) {
    console.error('Error fetching admin emails:', error.message);
    throw new Error('Unable to fetch admin emails from database');
  }
};

module.exports = { getAdminEmails };
