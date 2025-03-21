const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const crypto = require('crypto');
const multer = require("multer");
const path = require("path");
const User = require('./models/User');
const Chemical = require('./models/Chemical');
const Counter = require('./models/Counter');
const UserChemical = require('./models/UserChemical');
const nodemailer = require('nodemailer');
const OTP = require('./models/otp');
const fs = require("fs");
const ScrapChemical = require('./models/ScrapChemical');
const NewChemicalRequest = require('./models/NewChemicalRequest');
const axios = require('axios');

const API_URL = 'https://labrecordsbackend.onrender.com';
// const API_URL = 'http://localhost:5000';
dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({
    origin: 'https://indiumlabrecords.onrender.com',
    // origin: 'http://localhost:3000',
    
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// app.use(cors());

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

  // Transporter setup for nodemailer (adjust as necessary)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    // host: 'smtp.gmail.com',
    // port: 587,
    // secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
  });
  // Verify transporter
transporter.verify((error, success) => {
    if (error) {
      console.error('Error with email configuration:', error);
    } else {
      console.log('Email transporter is ready');
    }
    });
    
    app.get("/", (req, res) => {
      res.send({ status: "Started" });
  });

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized: No Token' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Token Verification Error:', error.message);
        return res.status(401).json({ error: 'Invalid Token' });
    }
};


// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Ensure this folder exists or create it
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage: storage });

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword, role: role || 'user' });
        await user.save();
        res.status(201).json({ message: 'User Registered Successfully' });
    } catch (error) {
        console.error('Registration Error:', error.message);
        res.status(500).json({ error: 'Server Error', details: error.message });
    }
});

// User Login
// app.post('/login', async (req, res) => {
//     try {
//         const { email, password } = req.body;
//         const user = await User.findOne({ email });
//         if (!user) return res.status(400).json({ error: 'User not found' });

//         const isMatch = await bcrypt.compare(password, user.password);
//         if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

//         const token = jwt.sign(
//             { id: user._id, name: user.name, role: user.role },
//             process.env.JWT_SECRET,
//             { expiresIn: '1h' }
//         );
//         res.json({ token, role: user.role });
//     } catch (error) {
//         console.error('Login Error:', error.message);
//         res.status(500).json({ error: 'Server Error', details: error.message });
//     }
// });

app.post('/login', async (req, res) => {
  try {
      const { email, password, captcha } = req.body;

      // Verify reCAPTCHA
      if (!captcha) {
          return res.status(400).json({ error: 'CAPTCHA is required' });
      }

      const verificationURL = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captcha}`;
      const verificationResponse = await axios.post(verificationURL);

      if (!verificationResponse.data.success) {
          console.error('reCAPTCHA verification failed:', verificationResponse.data);
          return res.status(400).json({ error: 'CAPTCHA verification failed' });
      }

      // Proceed with authentication
      const user = await User.findOne({ email });
      if (!user) return res.status(400).json({ error: 'User not found' });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

      const token = jwt.sign(
          { id: user._id, name: user.name, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
      );
      res.json({ token, role: user.role });
  } catch (error) {
      console.error('Login Error:', error.message);
      res.status(500).json({ error: 'Server Error', details: error.message });
  }
});

// Forgot Password
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ status: 'error', data: 'User not found' });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiresAt = new Date(Date.now() + 15 * 60 * 1000);

    user.resetPasswordOTP = otp;
    user.resetPasswordExpires = otpExpiresAt;
    await user.save();

    await OTP.findOneAndUpdate(
        { email }, // Find existing entry by email
        { otp, expiresAt: otpExpiresAt }, // Update OTP and expiry
        { upsert: true, new: true } // Create if not exists, return new doc
      );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}. It expires in 15 minutes.`,
    };

    await transporter.sendMail(mailOptions);
    res.json({ status: 'success', data: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.json({ status: 'error', data: error.message });
  }
});


app.post('/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.json({ status: 'error', data: 'User not found' });
      }
  
      // Fetch OTP entry from OTP collection
      const userOtpEntry = await OTP.findOne({ email });
  
      if (!userOtpEntry || userOtpEntry.otp !== otp) {
        return res.json({ status: 'error', data: 'Invalid OTP' });
      }
  
      // Check if OTP is expired
      if (userOtpEntry.expiresAt < new Date()) {
        return res.json({ status: 'error', data: 'OTP has expired' });
      }
  
      // Hash new password and update user
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();
  
      // Delete OTP entry after successful reset
      await OTP.deleteOne({ email });
  
      res.json({ status: 'success', data: 'Password reset successful' });
    } catch (error) {
      console.error('Reset password error:', error);
      res.json({ status: 'error', data: error.message });
    }
  });
  

// Get User Role
app.get('/userRole', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ role: user.role });
    } catch (error) {
        console.error('User Role Error:', error.message);
        res.status(500).json({ error: 'Server Error', details: error.message });
    }
});




// Add this endpoint after your other routes
app.post('/resetChemicalCounter', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
  try {
    // Reset the counter for 'chemicalId' to 0
    const counter = await Counter.findOneAndUpdate(
      { name: 'chemicalId' },
      { value: 0 },
      { new: true, upsert: true } // upsert ensures it creates if it doesn't exist
    );
    
    console.log(`[RESET] Chemical ID counter reset to 0 by user ${req.user.name}`);
    res.status(200).json({ message: 'Chemical ID counter reset successfully' });
  } catch (error) {
    console.error('Reset Counter Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});


app.post('/addChemical', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
  try {
    console.log('Incoming request body:', req.body); // Debug log
    const {
      chemicalName,
      chemicalType,
      type,
      gramsAvailable,
      make,
      dateOfMFG,
      dateOfExp,
      purchase,
      purchaseDate,
      invoiceNumber,
      isAbsolute,
      isApproximately,
      rack
    } = req.body;

    if (!chemicalName) {
      return res.status(400).json({ error: 'Chemical name is required' });
    }

    let counter = await Counter.findOneAndUpdate(
      { name: 'chemicalId' },
      { $inc: { value: 1 } },
      { new: true, upsert: true }
    );
    const chemicalId = `MURTI-BLR/INDIUM/BRL-${String(counter.value).padStart(3, '0')}`;

    const newChemical = new Chemical({
      chemicalId,
      chemicalName: chemicalName.toUpperCase(),
      chemicalType,
      type,
      gramsAvailable,
      make,
      dateOfMFG,
      dateOfExp,
      purchase,
      purchaseDate: purchaseDate ? new Date(purchaseDate) : new Date(),
      invoiceNumber,
      isAbsolute: isAbsolute || false,
      isApproximately: isApproximately || false,
      rack
    });

    await newChemical.save();
    res.status(201).json({ message: 'Chemical added successfully', chemicalId });
  } catch (error) {
    console.error('Add Chemical Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});

// Get All Chemicals
// app.get('/getchemicals', authenticate, async (req, res) => {
//     try {
//         const chemicals = await Chemical.find();
//         res.json(chemicals);
//     } catch (error) {
//         console.error('Get Chemicals Error:', error.message);
//         res.status(500).json({ error: 'Server Error', details: error.message });
//     }
// });

// Get All Chemicals with User Usage Data (for Admins)
app.get('/getchemicals', authenticate, async (req, res) => {
  try {
    // Fetch all chemicals
    const chemicals = await Chemical.find().lean();

    // If the user is an admin, enrich the data with user usage info
    if (req.user.role === 'admin') {
      const chemicalIds = chemicals.map(chem => chem.chemicalId);

      // Aggregate user usage data for these chemicals
      const usageData = await UserChemical.aggregate([
        { $match: { chemicalId: { $in: chemicalIds } } },
        {
          $group: {
            _id: '$chemicalId',
            users: {
              $push: {
                userName: '$name',
                gramsUsed: '$gramsUsed',
                date: '$date'
              }
            }
          }
        }
      ]);

      // Map usage data to chemicals
      const usageMap = new Map(usageData.map(item => [item._id, item.users]));
      chemicals.forEach(chem => {
        chem.userUsage = usageMap.get(chem.chemicalId) || [];
      });
    }

    res.json(chemicals);
  } catch (error) {
    console.error('Get Chemicals Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});

// Request Chemical
app.post('/requestChemical', authenticate, async (req, res) => {
    try {
        const { chemicalId, requestedGrams } = req.body;
        if (!chemicalId || !requestedGrams) return res.status(400).json({ error: 'Chemical ID and grams required' });

        const grams = parseFloat(requestedGrams);
        if (isNaN(grams) || grams <= 0) return res.status(400).json({ error: 'Invalid grams value' });

        const chemical = await Chemical.findOne({ chemicalId });
        if (!chemical) return res.status(404).json({ error: 'Chemical not found' });
        if (chemical.gramsAvailable < grams) return res.status(400).json({ error: 'Not enough stock' });

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });

        chemical.gramsAvailable -= grams;
        await chemical.save();

        const userChemical = new UserChemical({
            userId: req.user.id,
            chemicalId: chemical.chemicalId,
            chemicalName: chemical.chemicalName,
            gramsUsed: grams,
            date: new Date(),
            name: user.name
        });
        await userChemical.save();

        res.status(200).json({
            message: 'Chemical issued successfully',
            updatedStock: chemical.gramsAvailable
        });
    } catch (error) {
        console.error('Request Chemical Error:', error.message);
        res.status(500).json({ error: 'Server Error', details: error.message });
    }
});

// Get User Chemicals
app.get('/getUserChemicals', authenticate, async (req, res) => {
    try {
        let userChemicals;
        if (req.user.role === 'admin') {
            userChemicals = await UserChemical.find().lean();
        } else {
            userChemicals = await UserChemical.find({ userId: req.user.id }).lean();
        }
        res.json(userChemicals);
    } catch (error) {
        console.error('Get User Chemicals Error:', error.message);
        res.status(500).json({ error: 'Server Error', details: error.message });
    }
});

// Get User Details
app.get('/getUserDetails', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ userName: user.name });
    } catch (error) {
        console.error('Get User Details Error:', error.message);
        res.status(500).json({ error: 'Server Error', details: error.message });
    }
});

// Update Chemical
// app.put('/updateChemical/:chemicalId', authenticate, async (req, res) => {
//   if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
//   try {
//       const { chemicalId } = req.params;
//       const { gramsAvailable, dateOfMFG, dateOfExp, purchase } = req.body;
//       console.log(`[PUT] Request received for chemicalId: "${chemicalId}" (length: ${chemicalId.length})`);
//       console.log(`[PUT] Request body: ${JSON.stringify(req.body)}`);

//       // Trim the chemicalId to remove any accidental whitespace
//       const trimmedChemicalId = chemicalId.trim();
//       console.log(`[PUT] Trimmed chemicalId: "${trimmedChemicalId}"`);

//       // Log all chemical IDs in the database for comparison
//       const allChemicals = await Chemical.find({}, 'chemicalId');
//       console.log(`[PUT] All chemical IDs in DB: ${JSON.stringify(allChemicals.map(c => c.chemicalId))}`);

//       // Check if the chemical exists
//       const chemical = await Chemical.findOne({ chemicalId: trimmedChemicalId });
//       if (!chemical) {
//           console.log(`[PUT] No chemical found with chemicalId: "${trimmedChemicalId}"`);
//           return res.status(404).json({ error: `Chemical with ID "${trimmedChemicalId}" not found` });
//       }
//       console.log(`[PUT] Found chemical: ${JSON.stringify(chemical)}`);

//       // Validation
//       if (gramsAvailable === undefined || !dateOfMFG || !dateOfExp) {
//           return res.status(400).json({ error: 'Missing required fields (gramsAvailable, dateOfMFG, dateOfExp)' });
//       }

//       const grams = parseFloat(gramsAvailable);
//       if (isNaN(grams) || grams < 0) {
//           return res.status(400).json({ error: 'Invalid gramsAvailable value' });
//       }

//       const mfgDate = new Date(dateOfMFG);
//       const expDate = new Date(dateOfExp);
//       if (isNaN(mfgDate.getTime()) || isNaN(expDate.getTime())) {
//           return res.status(400).json({ error: 'Invalid date format for dateOfMFG or dateOfExp' });
//       }

//       const purchaseValue = purchase !== undefined ? parseFloat(purchase) : undefined;
//       if (purchaseValue !== undefined && (isNaN(purchaseValue) || purchaseValue < 0)) {
//           return res.status(400).json({ error: 'Invalid purchase value' });
//       }

//       // Update the chemical
//       const updatedChemical = await Chemical.findOneAndUpdate(
//           { chemicalId: trimmedChemicalId },
//           { 
//               gramsAvailable: grams, 
//               dateOfMFG: mfgDate, 
//               dateOfExp: expDate, 
//               ...(purchaseValue !== undefined && { purchase: purchaseValue }) 
//           },
//           { new: true, runValidators: true }
//       );

//       console.log(`[PUT] Updated chemical: ${JSON.stringify(updatedChemical)}`);
//       res.json({ message: 'Chemical updated successfully', chemical: updatedChemical });
//   } catch (error) {
//       console.error('[PUT] Error updating chemical:', {
//           chemicalId: req.params.chemicalId,
//           requestBody: req.body,
//           message: error.message,
//           stack: error.stack
//       });
//       res.status(500).json({ error: 'Server Error', details: error.message });
//   }
// });

// ... (previous imports and middleware remain unchanged)

// Update Chemical Endpoint
app.put('/updateChemical/:chemicalId', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
  try {
    const { chemicalId } = req.params;
    const { gramsAvailable, dateOfMFG, dateOfExp, purchase, purchaseDate } = req.body;
    console.log(`[PUT] Request received for chemicalId: "${chemicalId}" (length: ${chemicalId.length})`);
    console.log(`[PUT] Request body: ${JSON.stringify(req.body)}`);

    const trimmedChemicalId = chemicalId.trim();
    console.log(`[PUT] Trimmed chemicalId: "${trimmedChemicalId}"`);

    const allChemicals = await Chemical.find({}, 'chemicalId');
    console.log(`[PUT] All chemical IDs in DB: ${JSON.stringify(allChemicals.map(c => c.chemicalId))}`);

    const chemical = await Chemical.findOne({ chemicalId: trimmedChemicalId });
    if (!chemical) {
      console.log(`[PUT] No chemical found with chemicalId: "${trimmedChemicalId}"`);
      return res.status(404).json({ error: `Chemical with ID "${trimmedChemicalId}" not found` });
    }
    console.log(`[PUT] Found chemical: ${JSON.stringify(chemical)}`);

    if (gramsAvailable === undefined || !dateOfMFG || !dateOfExp) {
      return res.status(400).json({ error: 'Missing required fields (gramsAvailable, dateOfMFG, dateOfExp)' });
    }

    const grams = parseFloat(gramsAvailable);
    if (isNaN(grams) || grams < 0) {
      return res.status(400).json({ error: 'Invalid gramsAvailable value' });
    }

    const mfgDate = new Date(dateOfMFG);
    const expDate = new Date(dateOfExp);
    if (isNaN(mfgDate.getTime()) || isNaN(expDate.getTime())) {
      return res.status(400).json({ error: 'Invalid date format for dateOfMFG or dateOfExp' });
    }

    const purchaseValue = purchase !== undefined ? parseFloat(purchase) : undefined;
    if (purchaseValue !== undefined && (isNaN(purchaseValue) || purchaseValue < 0)) {
      return res.status(400).json({ error: 'Invalid purchase value' });
    }

    const purchaseDateValue = purchaseDate ? new Date(purchaseDate) : undefined;
    if (purchaseDate && isNaN(purchaseDateValue.getTime())) {
      return res.status(400).json({ error: 'Invalid date format for purchaseDate' });
    }

    const updatedChemical = await Chemical.findOneAndUpdate(
      { chemicalId: trimmedChemicalId },
      {
        gramsAvailable: grams,
        dateOfMFG: mfgDate,
        dateOfExp: expDate,
        ...(purchaseValue !== undefined && { purchase: purchaseValue }),
        ...(purchaseDateValue && { purchaseDate: purchaseDateValue }), // Update purchaseDate if provided
      },
      { new: true, runValidators: true }
    );

    console.log(`[PUT] Updated chemical: ${JSON.stringify(updatedChemical)}`);
    res.json({ message: 'Chemical updated successfully', chemical: updatedChemical });
  } catch (error) {
    console.error('[PUT] Error updating chemical:', {
      chemicalId: req.params.chemicalId,
      requestBody: req.body,
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});





// Delete Chemical
app.delete('/deleteChemical/:chemicalId', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
  try {
      const { chemicalId } = req.params;
      console.log(`[DELETE] Request received for chemicalId: "${chemicalId}" (length: ${chemicalId.length})`);

      // Log all chemicals to verify data
      const allChemicals = await Chemical.find();
      console.log(`[DELETE] All chemicals in DB: ${JSON.stringify(allChemicals.map(c => c.chemicalId))}`);

      // Check if the chemical exists
      const chemical = await Chemical.findOne({ chemicalId });
      if (!chemical) {
          console.log(`[DELETE] No chemical found with chemicalId: "${chemicalId}"`);
          return res.status(404).json({ error: `Chemical with ID "${chemicalId}" not found` });
      }

      console.log(`[DELETE] Found chemical: ${JSON.stringify(chemical)}`);

      // Attempt deletion
      const deletedChemical = await Chemical.findOneAndDelete({ chemicalId });
      if (!deletedChemical) {
          console.log(`[DELETE] Deletion failed for chemicalId: "${chemicalId}"`);
          return res.status(500).json({ error: 'Failed to delete chemical' });
      }

      console.log(`[DELETE] Successfully deleted chemicalId: "${chemicalId}"`);
      res.json({ message: 'Chemical deleted successfully' });
  } catch (error) {
      console.error('[DELETE] Error:', {
          chemicalId: req.params.chemicalId,
          message: error.message,
          stack: error.stack
      });
      res.status(500).json({ error: 'Server Error', details: error.message });
  }
});






// New Chemical Request Endpoint
app.post('/newChemicalRequest', authenticate, async (req, res) => {
  try {
    const { chemicalName } = req.body;
    if (!chemicalName) return res.status(400).json({ error: 'Chemical name required' });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: `${process.env.ADMIN_EMAIL} ,  ${process.env.ADMIN_EMAIL1} , ${process.env.ADMIN_EMAIL2}`,
      subject: `New Chemical Request from ${user.name} - ${chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <h2 style="color: #2c3e50;">New Chemical Request Notification</h2>
          <p>Dear Admin,</p>
          <p>A user has submitted a request for a new chemical to be added to the inventory. Please review the details below:</p>
          
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>User Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${user.name}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Requested Chemical Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemicalName}</td>
            </tr>
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Request Date:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
            </tr>
          </table>

          <p>Please evaluate this request and consider adding the requested chemical to the inventory. If further clarification is needed, you may contact the user directly.</p>
          
          <p>Best regards,</p>
          <p><strong>Chemical Management System</strong><br>
          Automated Notification Service<br>
          <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a></p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="font-size: 12px; color: #777;">This is an automated email. Please do not reply directly to this message.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'New chemical request sent to admin successfully' });
  } catch (error) {
    console.error('New Chemical Request Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});



// new  chemical request 

app.post('/scrapRequest', authenticate, upload.single("scrapPhoto"), async (req, res) => {
  try {
    const { chemicalId } = req.body;
    const scrapPhoto = req.file;

    if (!chemicalId) return res.status(400).json({ error: 'Chemical ID required' });
    if (!scrapPhoto) return res.status(400).json({ error: 'Photo upload required' });

    const chemical = await Chemical.findOne({ chemicalId });
    if (!chemical) return res.status(404).json({ error: 'Chemical not found' });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const approveToken = jwt.sign({ chemicalId, action: 'approve', userId: req.user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const denyToken = jwt.sign({ chemicalId, action: 'deny', userId: req.user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    const approveLink = `${API_URL}/scrap/approve/${approveToken}`;
    const denyLink = `${API_URL}/scrap/deny/${denyToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: `${process.env.ADMIN_EMAIL}, ${process.env.ADMIN_EMAIL1}, ${process.env.ADMIN_EMAIL2}`,
      subject: `Scrap Request Notification for ${chemical.chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <h2 style="color: #2c3e50;">Scrap Request Notification</h2>
          <p>Dear Administrators,</p>
          <p>A user has submitted a request to scrap a chemical from the inventory. Please review the details below:</p>
          
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>User Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${user.name}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemical.chemicalName}</td>
            </tr>
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical ID:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemicalId}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Request Date:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
            </tr>
          </table>
    
          <p>Please review the attached photo and take appropriate action using the links below:</p>
          <div style="margin: 20px 0;">
            <a href="${approveLink}" style="display: inline-block; padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">Approve Scrap Request</a>
            <a href="${denyLink}" style="display: inline-block; padding: 10px 20px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin-left: 15px;">Deny Scrap Request</a>
          </div>
    
          <p>If you need additional information, please contact the requesting user or the support team.</p>
          
          <p>Best regards,</p>
          <p><strong>Chemical Management System</strong><br>
          Automated Notification Service<br>
          <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a></p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="font-size: 12px; color: #777;">This is an automated email. Please do not reply directly to this message.</p>
        </div>
      `,
    
      attachments: [{
        filename: scrapPhoto.originalname,
        path: scrapPhoto.path,
      }],
    };

    await transporter.sendMail(mailOptions);
    fs.unlinkSync(scrapPhoto.path); // Delete the file after sending email
    res.status(200).json({ message: 'Scrap request with photo sent to admin successfully' });
  } catch (error) {
    console.error('Scrap Request Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});

// app.get('/scrap/approve/:token', async (req, res) => {
//   try {
//     const { token } = req.params;
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     if (decoded.action !== 'approve') return res.status(400).json({ error: 'Invalid token' });

//     const { chemicalId, userId } = decoded;
//     const chemical = await Chemical.findOne({ chemicalId });
//     const user = await User.findById(userId);
//     if (!chemical || !user) return res.status(404).json({ error: 'Chemical or user not found' });

//     if (!ScrapChemical) throw new Error('ScrapChemical model not defined');
//     const scrapChemical = new ScrapChemical({
//       chemicalId,
//       chemicalName: chemical.chemicalName,
//       userName: user.name,
//       date: new Date(),
//       status: 'approved'
//     });
//     await scrapChemical.save();

//     await Chemical.findOneAndDelete({ chemicalId }); // Optional deletion

//     res.send('<h1>Scrap Request Approved</h1><p>The chemical has been marked as scrapped.</p>');
//   } catch (error) {
//     console.error('Scrap Approve Error:', error.message);
//     res.status(500).send(`Server Error: ${error.message}`);
//   }
// });

// old
// app.get('/scrap/approve/:token', async (req, res) => {
//   try {
//     const { token } = req.params;
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     if (decoded.action !== 'approve') return res.status(400).json({ error: 'Invalid token' });

//     const { chemicalId, userId } = decoded;
//     const chemical = await Chemical.findOne({ chemicalId });
//     const user = await User.findById(userId);
//     if (!chemical || !user) return res.status(404).json({ error: 'Chemical or user not found' });

//     const scrapChemical = new ScrapChemical({
//       chemicalId,
//       chemicalName: chemical.chemicalName,
//       userName: user.name,
//       date: new Date(),
//       status: 'approved'
//     });
//     await scrapChemical.save();

//     await Chemical.findOneAndDelete({ chemicalId }); // Optional: delete from inventory

//     res.send('<h1>Scrap Request Approved</h1><p>The chemical has been marked as scrapped.</p>');
//   } catch (error) {
//     console.error('Scrap Approve Error:', error.message);
//     res.status(500).send(`Server Error: ${error.message}`);
//   }
// });

// new
// app.get('/scrap/approve/:token', async (req, res) => {
//   try {
//     const { token } = req.params;
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     if (decoded.action !== 'approve') return res.status(400).json({ error: 'Invalid token' });

//     const { chemicalId, userId } = decoded;
//     const chemical = await Chemical.findOne({ chemicalId });
//     const user = await User.findById(userId);
//     if (!chemical || !user) return res.status(404).json({ error: 'Chemical or user not found' });

//     const scrapChemical = new ScrapChemical({
//       chemicalId,
//       chemicalName: chemical.chemicalName,
//       userName: user.name,
//       date: new Date(),
//       status: 'approved',
//     });
//     await scrapChemical.save();

//     await Chemical.findOneAndDelete({ chemicalId }); // Delete from inventory

//     // Send email notification to the requesting user
//     const mailOptions = {
//       from: process.env.EMAIL_USER,
//       to: user.email,
//       subject: `Scrap Request Approved for ${chemical.chemicalName}`,
//       html: `
//         <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
//           <h2 style="color: #2c3e50;">Scrap Request Approval Notification</h2>
//           <p>Dear ${user.name},</p>
//           <p>Your request to scrap the following chemical has been approved by an administrator:</p>
          
//           <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
//             <tr style="background-color: #f2f2f2;">
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical ID:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${chemicalId}</td>
//             </tr>
//             <tr>
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical Name:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${chemical.chemicalName}</td>
//             </tr>
//             <tr style="background-color: #f2f2f2;">
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Approval Date:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
//             </tr>
//             <tr>
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Status:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">Approved</td>
//             </tr>
//           </table>
          
//           <p>The chemical has been removed from the inventory and marked as scrapped. If you have any questions, please contact the administration team.</p>
          
//           <p>Best regards,</p>
//           <p><strong>Chemical Management System</strong><br>
//           Automated Notification Service<br>
//           <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a></p>
          
//           <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
//           <p style="font-size: 12px; color: #777;">This is an automated email. Please do not reply directly to this message.</p>
//         </div>
//       `,
//     };

//     await transporter.sendMail(mailOptions);

//     res.send('<h1>Scrap Request Approved</h1><p>The chemical has been marked as scrapped, and the user has been notified.</p>');
//   } catch (error) {
//     console.error('Scrap Approve Error:', error.message);
//     res.status(500).send(`Server Error: ${error.message}`);
//   }
// });


app.get('/scrap/approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'approve') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalId, userId } = decoded;
    const chemical = await Chemical.findOne({ chemicalId });
    const user = await User.findById(userId);
    if (!chemical || !user) return res.status(404).json({ error: 'Chemical or user not found' });

    const scrapChemical = new ScrapChemical({
      chemicalId,
      chemicalName: chemical.chemicalName,
      userName: user.name,
      date: new Date(),
      status: 'approved',
    });
    await scrapChemical.save();

    await Chemical.findOneAndDelete({ chemicalId }); // Delete from inventory

    // Send email notification to the requesting user
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `Scrap Request Approved for ${chemical.chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <h2 style="color: #2c3e50;">Scrap Request Approval Notification</h2>
          <p>Dear ${user.name},</p>
          <p>Your request to scrap the following chemical has been approved by an administrator:</p>
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical ID:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemicalId}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemical.chemicalName}</td>
            </tr>
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Approval Date:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Status:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">Approved</td>
            </tr>
          </table>
          <p>The chemical has been removed from the inventory and marked as scrapped.</p>
          <p>Best regards,</p>
          <p><strong>Chemical Management System</strong></p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    // Enhanced HTML response for admin
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scrap Request Approval</title>
        <style>
          body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f4; }
          .container { text-align: center; background-color: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
          h1 { color: #28a745; }
          p { color: #333; font-size: 18px; }
          .details { margin-top: 20px; text-align: left; }
          .details strong { color: #2c3e50; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Scrap Request Approval</h1>
          <p>The scrap request has been successfully approved.</p>
          <div class="details">
            <p><strong>Chemical ID:</strong> ${chemicalId}</p>
            <p><strong>Chemical Name:</strong> ${chemical.chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Approval Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The requesting user has been notified via email.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Scrap Approve Error:', error.message);
    res.status(500).send(`Server Error: ${error.message}`);
  }
});


app.get('/getScrapChemicals', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
  try {
    const scrapChemicals = await ScrapChemical.find().lean();
    res.json(scrapChemicals);
  } catch (error) {
    console.error('Get Scrap Chemicals Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});


// app.get('/scrap/deny/:token', async (req, res) => {
//   try {
//     const { token } = req.params;
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     if (decoded.action !== 'deny') return res.status(400).json({ error: 'Invalid token' });

//     const { chemicalId, userId } = decoded;
//     const user = await User.findById(userId);
//     const chemical = await Chemical.findOne({ chemicalId });
//     if (!user || !chemical) return res.status(404).json({ error: 'User or chemical not found' });

//     const mailOptions = {
//       from: process.env.EMAIL_USER,
//       to: user.email,
//       subject: 'Scrap Request Denial Notification',
//       html: `
//         <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
//           <h2 style="color: #2c3e50;">Scrap Request Denial Notification</h2>
//           <p>Dear ${user.name || 'User'},</p>
//           <p>We regret to inform you that your scrap request has been reviewed and denied by the administrator. Please find the details below:</p>
          
//           <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
//             <tr style="background-color: #f2f2f2;">
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical ID:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${chemicalId}</td>
//             </tr>
//             <tr>
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical Name:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${chemical.chemicalName}</td>
//             </tr>
//             <tr style="background-color: #f2f2f2;">
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Request Date:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
//             </tr>
//             <tr>
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Status:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">Denied</td>
//             </tr>
//           </table>
    
//           <p>If you have any questions or require further clarification regarding this decision, please feel free to contact the administration team.</p>
          
//           <p>Best regards,</p>
//           <p><strong>Chemical Management System</strong><br>
//           Automated Notification Service<br>
//           <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a></p>
          
//           <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
//           <p style="font-size: 12px; color: #777;">This is an automated email. Please do not reply directly to this message.</p>
//         </div>
//       `,
//     };
//     await transporter.sendMail(mailOptions);

//     res.send('<h1>Scrap Request Denied</h1><p>The user has been notified.</p>');
//   } catch (error) {
//     console.error('Scrap Deny Error:', error.message);
//     res.status(500).send('Server Error');
//   }
// });


app.get('/scrap/deny/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'deny') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalId, userId } = decoded;
    const user = await User.findById(userId);
    const chemical = await Chemical.findOne({ chemicalId });
    if (!user || !chemical) return res.status(404).json({ error: 'User or chemical not found' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Scrap Request Denial Notification',
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <h2 style="color: #2c3e50;">Scrap Request Denial Notification</h2>
          <p>Dear ${user.name || 'User'},</p>
          <p>Your scrap request has been reviewed and denied by the administrator:</p>
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical ID:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemicalId}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemical.chemicalName}</td>
            </tr>
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Denial Date:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Status:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">Denied</td>
            </tr>
          </table>
          <p>Please contact the admin team if you have questions.</p>
          <p>Best regards,</p>
          <p><strong>Chemical Management System</strong></p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    // Enhanced HTML response for admin
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scrap Request Denied</title>
        <style>
          body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f4; }
          .container { text-align: center; background-color: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
          h1 { color: #dc3545; }
          p { color: #333; font-size: 18px; }
          .details { margin-top: 20px; text-align: left; }
          .details strong { color: #2c3e50; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Scrap Request Denied</h1>
          <p>The scrap request has been denied.</p>
          <div class="details">
            <p><strong>Chemical ID:</strong> ${chemicalId}</p>
            <p><strong>Chemical Name:</strong> ${chemical.chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Denial Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The requesting user has been notified via email.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Scrap Deny Error:', error.message);
    res.status(500).send('Server Error');
  }
});

// app.post('/newChemicalRequest', authenticate, async (req, res) => {
//   try {
//     const { chemicalName } = req.body;
//     if (!chemicalName) return res.status(400).json({ error: 'Chemical name required' });

//     const user = await User.findById(req.user.id);
//     if (!user) return res.status(404).json({ error: 'User not found' });

//     const approveToken = jwt.sign({ chemicalName, action: 'approve', userId: req.user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
//     const denyToken = jwt.sign({ chemicalName, action: 'deny', userId: req.user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

//     const approveLink = `${process.env.BASE_URL || API_URL}/newChemical/approve/${approveToken}`;
//     const denyLink = `${process.env.BASE_URL || API_URL}/newChemical/deny/${denyToken}`;

//     const mailOptions = {
//       from: process.env.EMAIL_USER,
//       to: `${process.env.ADMIN_EMAIL}, ${process.env.ADMIN_EMAIL1}, ${process.env.ADMIN_EMAIL2}`,
//       subject: `New Chemical Request Notification `,
//       html: `
//         <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
//           <h2 style="color: #2c3e50;">New Chemical Request Notification</h2>
//           <p>Dear Administrators,</p>
//           <p>We have received a new chemical request from one of our users. Please find the details below:</p>
          
//           <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
//             <tr style="background-color: #f2f2f2;">
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>User Name:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${user.name}</td>
//             </tr>
//             <tr>
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical Name:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${chemical.chemicalName}</td>
//             </tr>
//             <tr style="background-color: #f2f2f2;">
//               <td style="padding: 10px; border: 1px solid #ddd;"><strong>Request Date:</strong></td>
//               <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
//             </tr>
//           </table>
    
//           <p>Please review this request at your earliest convenience and take appropriate action using the links below:</p>
//           <div style="margin: 20px 0;">
//             <a href="${approveLink}" style="display: inline-block; padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">Approve Request</a>
//             <a href="${denyLink}" style="display: inline-block; padding: 10px 20px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin-left: 15px;">Deny Request</a>
//           </div>
    
//           <p>If you need additional information, please feel free to contact the requesting user or the support team.</p>
          
//           <p>Best regards,</p>
//           <p><strong>Chemical Management System</strong><br>
//           Automated Notification Service<br>
//           <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a></p>
          
//           <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
//           <p style="font-size: 12px; color: #777;">This is an automated email. Please do not reply directly to this message.</p>
//         </div>
//       `,
//     };

//     await transporter.sendMail(mailOptions);
//     res.status(200).json({ message: 'New chemical request sent to admin successfully' });
//   } catch (error) {
//     console.error('New Chemical Request Error:', error.message);
//     res.status(500).json({ error: 'Server Error', details: error.message });
//   }
// });



app.get('/newChemical/approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'approve') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalName, userId } = decoded;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const newChemicalRequest = new NewChemicalRequest({
      chemicalName,
      userName: user.name,
      date: new Date(),
      status: 'approved', // Optional: track status
    });
    await newChemicalRequest.save();

    // Notify the user
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `New Chemical Request Approved for ${chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <h2 style="color: #2c3e50;">New Chemical Request Approval Notification</h2>
          <p>Dear ${user.name},</p>
          <p>Your request for a new chemical has been approved by an administrator:</p>
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemicalName}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Approval Date:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
            </tr>
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Status:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">Approved</td>
            </tr>
          </table>
          <p>The chemical will be added to the inventory soon. Contact the admin team for further details.</p>
          <p>Best regards,</p>
          <p><strong>Chemical Management System</strong></p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    // Enhanced HTML response for admin
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Chemical Request Approval</title>
        <style>
          body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f4; }
          .container { text-align: center; background-color: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
          h1 { color: #28a745; }
          p { color: #333; font-size: 18px; }
          .details { margin-top: 20px; text-align: left; }
          .details strong { color: #2c3e50; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>New Chemical Request Approval</h1>
          <p>The new chemical request has been successfully approved.</p>
          <div class="details">
            <p><strong>Chemical Name:</strong> ${chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Approval Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The requesting user has been notified via email.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('New Chemical Approve Error:', error.message);
    res.status(500).send('Server Error');
  }
});


app.get('/newChemical/deny/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'deny') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalName, userId } = decoded;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'New Chemical Request Denied Notification',
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <h2 style="color: #2c3e50;">New Chemical Request Denial Notification</h2>
          <p>Dear ${user.name || 'User'},</p>
          <p>Your request for a new chemical has been reviewed and denied by the administrator:</p>
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Chemical Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${chemicalName}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Denial Date:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
            </tr>
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Status:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">Denied</td>
            </tr>
          </table>
          <p>Please contact the admin team if you have questions.</p>
          <p>Best regards,</p>
          <p><strong>Chemical Management System</strong></p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    // Enhanced HTML response for admin
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Chemical Request Denied</title>
        <style>
          body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f4; }
          .container { text-align: center; background-color: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
          h1 { color: #dc3545; }
          p { color: #333; font-size: 18px; }
          .details { margin-top: 20px; text-align: left; }
          .details strong { color: #2c3e50; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>New Chemical Request Denied</h1>
          <p>The new chemical request has been denied.</p>
          <div class="details">
            <p><strong>Chemical Name:</strong> ${chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Denial Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The requesting user has been notified via email.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('New Chemical Deny Error:', error.message);
    res.status(500).send('Server Error');
  }
});



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
