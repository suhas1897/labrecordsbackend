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
const ScrapRequest = require('./models/ScrapChemical');
const NewChemicalRequest = require('./models/NewChemicalRequest');
const axios = require('axios');
const { getAdminEmails } = require('./models/role');

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



app.post('/register', async (req, res) => {
  try {
    const { name, email, password, role, salutation, designation, department, contactNumber, joiningDate } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        error: 'Registration Failed', 
        details: 'A user with this email address already exists.' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ 
      name, 
      email, 
      password: hashedPassword, 
      role: role || 'user', 
      salutation, 
      designation, 
      department, 
      contactNumber, 
       
      joiningDate: new Date(joiningDate),
      status: 'pending' 
    });
    await user.save();

    const { adminEmails } = await getAdminEmails();
    console.log(adminEmails);
    if (!adminEmails || adminEmails.length === 0) {
      console.error('No approved admins found in the database');
      return res.status(500).json({ 
        error: 'Server Error', 
        details: 'No admin email available. Please contact support.' 
      });
    }

    const approveToken = jwt.sign({ userId: user._id, action: 'approve' }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const denyToken = jwt.sign({ userId: user._id, action: 'deny' }, process.env.JWT_SECRET, { expiresIn: '7d' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: adminEmails, // Array of admin emails
      subject: `User Registration Approval Request for ${salutation} ${name}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
  <!-- Logo Header -->
  <div style="text-align: left; margin-bottom: 25px; text-align: center;">
    <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
  </div>

  <!-- Title -->
  <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">New User Registration - Action Required</h2>

  <!-- Greeting and Intro -->
  <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear Admin,</p>
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">A new user has registered with the Chemical Management System and requires your approval. Please review the details below and approve or deny the request:</p>

  <!-- Details Table -->
  <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Name</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${salutation} ${name}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Email</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">
      <a href="mailto:${email}" style="color: #f0e0c1; text-decoration: none;">${email}</a>
    </td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Role</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${role || 'user'}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Designation</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${designation}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Department</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${department}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Contact Number</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${contactNumber}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Registration Date</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
    </tr>
  </table>

  <!-- Action Prompt -->
  <p style="font-size: 15px; margin: 0 0 20px; color: #444;">Please take one of the following actions:</p>
  <div style="text-align: center; margin: 0 0 25px;">
    <a href="${API_URL}/user/approve/${approveToken}" 
       style="display: inline-block; padding: 12px 28px; background-color: #2ecc71; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
      Approve
    </a>
    <a href="${API_URL}/user/deny/${denyToken}" 
       style="display: inline-block; padding: 12px 28px; background-color: #e74c3c; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
      Deny
    </a>
  </div>

  <!-- Contact Prompt -->
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">If you have questions or need more information, please contact support at <a href="mailto:${process.env.EMAIL_USER}" style="color: #2980b9; text-decoration: none; font-weight: 500;">${process.env.EMAIL_USER}</a>.</p>

  <!-- Footer -->
  <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
    <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
    <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
    <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #003d36;">CIMS – Chemical Inventory Management System</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
      📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(6, 46, 73); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
      | 📞 +91 9191080 48750  
    </p>
    <p style="font-size: 13px; margin: 0; color: #666;">
      <a href="https://www.indiumlaboratory.com/" style="color: rgb(6, 46, 73); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
    </p>
  </div>

  <!-- Disclaimer -->
  <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
  <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
    This is an automated notification from CIMS. Please do not reply directly to this email. 
    For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
  </p>
</div>
      `
    };
    await transporter.sendMail(mailOptions);

    res.status(201).json({ 
      message: 'Registration Successful', 
      details: 'Your account has been registered and is awaiting admin approval. You will be notified once approved.' 
    });
  } catch (error) {
    console.error('Registration Error:', error.message);
    res.status(500).json({ 
      error: 'Server Error', 
      details: 'An unexpected error occurred during registration. Please try again later or contact support.' 
    });
  }
});





app.get('/user/approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Decoded Token:', decoded);
    if (decoded.action !== 'approve') return res.status(400).json({ error: 'Invalid token' });

    const user = await User.findById(decoded.userId);
    if (!user) {
      console.log('User not found for userId:', decoded.userId);
      return res.status(404).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>User Not Found</title>
          <style>
            body {
              font-family: 'Arial', sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 100vh;
              margin: 0;
              background-color: #f4f4f9;
            }
            .container {
              text-align: center;
              background-color: #ffffff;
              padding: 40px;
              border-radius: 12px;
              box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
              max-width: 500px;
              width: 90%;
            }
            h1 {
              color: #dc3545;
              font-size: 28px;
              margin-bottom: 20px;
            }
            p {
              color: #444;
              font-size: 18px;
              margin: 10px 0;
            }
            .footer {
              margin-top: 20px;
              font-size: 14px;
              color: #777;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Error: User Not Found</h1>
            <p>The user associated with this registration request could not be found.</p>
            <p>This may be due to the request being deleted or already denied.</p>
            <p class="footer">If you believe this is an error, please contact support at <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a>.</p>
          </div>
        </body>
        </html>
      `);
    }



    const { superAdminEmails, adminEmails } = await getAdminEmails();
console.log(superAdminEmails, adminEmails);

    if (user.status === 'pending') {
      const superApproveToken = jwt.sign({ userId: user._id, action: 'super_approve' }, process.env.JWT_SECRET, { expiresIn: '7d' });
      const superDenyToken = jwt.sign({ userId: user._id, action: 'super_deny' }, process.env.JWT_SECRET, { expiresIn: '7d' });

      if (!superAdminEmails) {
        return res.status(500).json({ error: 'Server Error', details: 'Super admin email not configured' });
      }

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: superAdminEmails,
        subject: `Final Approval Required for ${user.salutation} ${user.name}`,
        html: `
          <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
  <!-- Logo Header -->
  <div style="text-align: left; margin-bottom: 25px; text-align: center;">
    <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
  </div>

  <!-- Title -->
  <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">User Registration - Final Approval Required</h2>

  <!-- Greeting and Intro -->
  <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear Super Admin,</p>
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">An admin has reviewed and approved the following user registration. Please provide your final approval or denial:</p>

  <!-- Details Table -->
  <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Name</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.salutation} ${user.name}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Email</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.email}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Role</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.role}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Designation</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.designation}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Department</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.department}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Contact Number</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.contactNumber}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Request Date</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
    </tr>
  </table>

  <!-- Action Prompt -->
  <p style="font-size: 15px; margin: 0 0 20px; color: #444;">Please take one of the following actions:</p>
  <div style="text-align: center; margin: 0 0 25px;">
    <a href="${API_URL}/user/super/approve/${superApproveToken}" 
       style="display: inline-block; padding: 12px 28px; background-color: #2ecc71; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
      Approve
    </a>
    <a href="${API_URL}/user/super/deny/${superDenyToken}" 
       style="display: inline-block; padding: 12px 28px; background-color: #e74c3c; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
      Deny
    </a>
  </div>

  <!-- Contact Prompt -->
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">If you need additional information, please contact the admin team at <a href="mailto:${process.env.EMAIL_USER}" style="color: #2980b9; text-decoration: none; font-weight: 500;">${process.env.EMAIL_USER}</a>.</p>

  <!-- Footer -->
  <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
    <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
    <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
    <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
      📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
      | 📞 +91 9191080 48750
    </p>
    <p style="font-size: 13px; margin: 0; color: #666;">
      <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
    </p>
  </div>

  <!-- Disclaimer -->
  <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
  <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
    This is an automated notification from CIMS. Please do not reply directly to this email. 
    For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
  </p>
</div>
        `
      };
      await transporter.sendMail(mailOptions);

      res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Approval Sent to Super Admin</title>
          <style>
            body {
              font-family: 'Arial', sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 100vh;
              margin: 0;
              background-color: #f4f4f9;
            }
            .container {
              text-align: center;
              background-color: #ffffff;
              padding: 40px;
              border-radius: 12px;
              box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
              max-width: 500px;
              width: 90%;
            }
            h1 {
              color: #007bff;
              font-size: 28px;
              margin-bottom: 20px;
            }
            p {
              color: #444;
              font-size: 18px;
              margin: 10px 0;
            }
            .details {
              margin-top: 25px;
              text-align: left;
              background-color: #f9f9f9;
              padding: 15px;
              border-radius: 8px;
              border: 1px solid #eee;
            }
            .details p {
              margin: 8px 0;
              font-size: 16px;
            }
            .details strong {
              color: #2c3e50;
              font-weight: 600;
            }
            .footer {
              margin-top: 30px;
              font-size: 14px;
              color: #777;
            }
            a.back-btn {
              display: inline-block;
              margin-top: 20px;
              padding: 10px 20px;
              background-color: #007bff;
              color: white;
              text-decoration: none;
              border-radius: 5px;
              font-weight: 500;
              transition: background-color 0.3s;
            }
            a.back-btn:hover {
              background-color: #0056b3;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Approval Sent</h1>
            <p>The user registration has been approved and sent to the Super Admin for final review.</p>
            <div class="details">
              <p><strong>Name:</strong>${user.salutation} ${user.name}</p>
              <p><strong>Email:</strong> ${user.email}</p>
              <p><strong>Role:</strong> ${user.role}</p>
              <p><strong>Designation:</strong> ${user.designation}</p>
              <p><strong>Department:</strong> ${user.department}</p>
              <p><strong>Contact Number:</strong> ${user.contactNumber}</p>
              <p><strong>Joining Date:</strong> ${user.joiningDate}</p>
              <p><strong>Submission Date:</strong> ${new Date().toLocaleDateString()}</p>
            </div>
            <p class="footer">The Super Admin has been notified via email.</p>
            <a href="${API_URL}" class="back-btn">Return to Dashboard</a>
          </div>
        </body>
        </html>
      `);
    } else {
      user.status = 'approved';
      await user.save();

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Account Approved',
        html: `
          <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2c3e50; text-align: center;">Account Approval Notification</h2>
            <p>Dear ${user.salutation} ${user.name},</p>
            <p>We are pleased to inform you that your account with the Chemical Management System has been approved. You can now log in and access the system.</p>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0; background-color: #f9f9f9; border: 1px solid #ddd;">
              <tr style="background-color: #f2f2f2;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Name:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${user.salutation}${user.name}</td>
              </tr>
              <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Email:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${user.email}</td>
              </tr>
              <tr style="background-color: #f2f2f2;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Role:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${user.role}</td>
              </tr>

              <tr style="background-color: #f2f2f2;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Department:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${user.department}</td>
              </tr>
              <tr style="background-color: #f2f2f2;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Contact Number:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${user.contactNumber}</td>
              </tr>
              <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Approval Date:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
              </tr>
            </table>

            <p>To get started, please log in using your registered email and password at <a href="${API_URL}" style="color: #007bff; text-decoration: none;">${API_URL}</a>.</p>
            
            <p>If you have any questions, feel free to contact our support team at <a href="mailto:${process.env.EMAIL_USER}" style="color: #007bff; text-decoration: none;">${process.env.EMAIL_USER}</a>.</p>
            
            <p style="margin-top: 30px;">Best regards,</p>
            <p><strong>Chemical Management System</strong><br>
            Automated Notification Service</p>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="font-size: 12px; color: #777; text-align: center;">This is an automated email. Please do not reply directly to this message.</p>
          </div>
        `
      };
      await transporter.sendMail(mailOptions);

      res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>User Approved</title>
          <style>
            body {
              font-family: 'Arial', sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 100vh;
              margin: 0;
              background-color: #f4f4f9;
            }
            .container {
              text-align: center;
              background-color: #ffffff;
              padding: 40px;
              border-radius: 12px;
              box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
              max-width: 500px;
              width: 90%;
            }
            h1 {
              color: #28a745;
              font-size: 28px;
              margin-bottom: 20px;
            }
            p {
              color: #444;
              font-size: 18px;
              margin: 10px 0;
            }
            .details {
              margin-top: 25px;
              text-align: left;
              background-color: #f9f9f9;
              padding: 15px;
              border-radius: 8px;
              border: 1px solid #eee;
            }
            .details p {
              margin: 8px 0;
              font-size: 16px;
            }
            .details strong {
              color: #2c3e50;
              font-weight: 600;
            }
            .footer {
              margin-top: 30px;
              font-size: 14px;
              color: #777;
            }
            a.back-btn {
              display: inline-block;
              margin-top: 20px;
              padding: 10px 20px;
              background-color: #007bff;
              color: white;
              text-decoration: none;
              border-radius: 5px;
              font-weight: 500;
              transition: background-color 0.3s;
            }
            a.back-btn:hover {
              background-color: #0056b3;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>User Approved</h1>
            <p>The user registration has been successfully approved.</p>
            <div class="details">
              <p><strong>Name:</strong> ${user.salutation} ${user.name}</p>
              <p><strong>Email:</strong> ${user.email}</p>
              <p><strong>Role:</strong> ${user.role}</p>
              <p><strong>Status:</strong> ${user.status}</p>
              <p><strong>Registration Date:</strong> ${user.createdAt.toLocaleDateString()}</p>
              <p><strong>Department:</strong> ${user.department}</p>
              <p><strong>Designation:</strong> ${user.designation}</p>
              <p><strong>Approval Date:</strong> ${new Date().toLocaleDateString()}</p>
            </div>
            <p class="footer">The user has been notified via email.</p>
            <a href="${API_URL}" class="back-btn">Return to Dashboard</a>
          </div>
        </body>
        </html>
      `);
    }
  } catch (error) {
    console.error('Approval Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});


app.get('/user/deny/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'deny') return res.status(400).json({ error: 'Invalid token' });

    const user = await User.findByIdAndDelete(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Account Registration Denied',
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
  <!-- Logo Header -->
  <div style="text-align: left; margin-bottom: 25px; text-align: center;">
    <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
  </div>

  <!-- Title -->
  <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Account Registration Denied</h2>

  <!-- Greeting and Intro -->
  <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.salutation} ${user.name},</p>
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">We regret to inform you that your registration request for the Chemical Management System has been denied. Below are the details of this decision:</p>

  <!-- Details Table -->
  <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Name</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.salutation} ${user.name}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Email</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.email}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Role</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.role}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Department</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.department}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Designation</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.designation}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Contact Number</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.contactNumber}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denial Date</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Status</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denied</td>
    </tr>
  </table>

  <!-- Contact Prompt -->
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">If you believe this decision was made in error or have any questions, please contact our support team at <a href="mailto:${process.env.EMAIL_USER}" style="color: #2980b9; text-decoration: none; font-weight: 500;">${process.env.EMAIL_USER}</a>.</p>

  <!-- Closing -->
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Thank you for your understanding.</p>

  <!-- Footer -->
  <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
    <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
    <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
    <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
      📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
      | 📞 +91 9191080 48750 
    </p>
    <p style="font-size: 13px; margin: 0; color: #666;">
      <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
    </p>
  </div>

  <!-- Disclaimer -->
  <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
  <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
    This is an automated notification from CIMS. Please do not reply directly to this email. 
    For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
  </p>
</div>
      `
    };
    await transporter.sendMail(mailOptions);

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>User Denied</title>
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
          <h1>User Denied</h1>
          <p>The user registration has been denied.</p>
          <div class="details">
            <p><strong>Name:</strong> ${user.salutation} ${user.name}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Role:</strong> ${user.role}</p>
            <p><strong>Designation:</strong> ${user.designation}</p>
            <p><strong>Contact Number:</strong> ${user.contactNumber}</p>
            <p><strong>Status:</strong> ${user.status}</p>
             <p><strong>Denial Date:</strong> ${new Date().toLocaleDateString()}</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Deny Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});

// Super Admin Final Approval
app.get('/user/super/approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'super_approve') return res.status(400).json({ error: 'Invalid token' });

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.status = 'approved';
    await user.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Your Account Has Been Approved',
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
  <!-- Logo Header -->
  <div style="text-align: left; margin-bottom: 25px; text-align: center;">
    <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
  </div>

  <!-- Title -->
  <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Account Approval Notification</h2>

  <!-- Greeting and Intro -->
  <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.salutation || ''} ${user.name},</p>
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">We are pleased to inform you that your account with the <strong>Chemical Management System</strong> has been fully approved by the Super Admin on ${new Date().toLocaleDateString()}.</p>

  <!-- Details Table -->
  <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Name</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.salutation} ${user.name}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Email</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.email}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Role</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.role}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Designation</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.designation}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Department</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.department}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Contact Number</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.contactNumber}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Joining Date</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date(user.joiningDate).toLocaleDateString()}</td>
    </tr>
  </table>

  <!-- Login Prompt -->
  <p style="font-size: 15px; margin: 0 0 20px; color: #444;">You can now log in to the system using your registered email and password. Click the button below to get started:</p>
  <div style="text-align: center; margin: 0 0 25px;">
    <a href="https://indiumlabrecords.onrender.com" 
       style="display: inline-block; padding: 12px 28px; background-color: #2ecc71; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; transition: background-color 0.3s;">
      Log In Now
    </a>
  </div>

  <!-- Support Contact -->
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">If you encounter any issues or have questions, feel free to contact our support team at <a href="mailto:${process.env.EMAIL_USER}" style="color: #2980b9; text-decoration: none; font-weight: 500;">${process.env.EMAIL_USER}</a>.</p>

  <!-- Footer -->
  <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
    <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
    <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Super Admin</p>
    <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
      📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
     📞 +91 99001 63967 , 	📞 +91 9080 856131

    </p>
    <p style="font-size: 13px; margin: 0; color: #666;">
      <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
    </p>
  </div>

  <!-- Disclaimer -->
  <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
  <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
    This is an automated notification from CIMS. Please do not reply directly to this email. 
    For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
  </p>
</div>
      `,
    };
    await transporter.sendMail(mailOptions);

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>User Approval</title>
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
          <h1>User Approved</h1>
          <p>The user has been fully approved by the Super Admin.</p>
          <div class="details">
            <p><strong>Name:</strong>${user.salutation} ${user.name}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Role:</strong> ${user.role}</p>
            <p><strong>Designation:</strong> ${user.designation}</p>
            <p><strong>Contact Number:</strong> ${user.contactNumber}</p>
            <p><strong>Status:</strong> ${user.status}</p>
            <p><strong>Approval Date:</strong> ${new Date().toLocaleDateString()}</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Super Admin Approve Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});




app.get('/user/super/deny/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'super_deny') return res.status(400).json({ error: 'Invalid token' });

    const user = await User.findByIdAndDelete(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Account Registration Denied',
      html: `
       <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
  <!-- Logo Header -->
  <div style="text-align: left; margin-bottom: 25px; text-align: center;">
    <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
  </div>

  <!-- Title -->
  <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Account Registration Denied</h2>

  <!-- Greeting and Intro -->
  <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.salutation} ${user.name},</p>
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">We regret to inform you that your registration request for the Chemical Management System has been denied by the Super Admin. Below are the details of this decision:</p>

  <!-- Details Table -->
  <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Name</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.salutation} ${user.name}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Email</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.email}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Role</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.role}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denial Date</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Status</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denied</td>
    </tr>
  </table>

  <!-- Contact Prompt -->
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">If you have any questions or believe this decision was made in error, please contact our support team at <a href="mailto:${process.env.EMAIL_USER}" style="color: #2980b9; text-decoration: none; font-weight: 500;">${process.env.EMAIL_USER}</a>.</p>

  <!-- Closing -->
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Thank you for your understanding.</p>

  <!-- Footer -->
  <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
    <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
    <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Super Admin</p>
    <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
      📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
      | 📞 +91 99001 63967 , 📞 +91 9080 856131

    </p>
    <p style="font-size: 13px; margin: 0; color: #666;">
      <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
    </p>
  </div>

  <!-- Disclaimer -->
  <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
  <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
    This is an automated notification from CIMS. Please do not reply directly to this email. 
    For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
  </p>
</div>
      `
    };
    await transporter.sendMail(mailOptions);

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>User Registration Denied</title>
        <style>
          body {
            font-family: 'Arial', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f4f4f9;
          }
          .container {
            text-align: center;
            background-color: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 90%;
          }
          h1 {
            color: #dc3545;
            font-size: 28px;
            margin-bottom: 20px;
          }
          p {
            color: #444;
            font-size: 18px;
            margin: 10px 0;
          }
          .details {
            margin-top: 25px;
            text-align: left;
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #eee;
          }
          .details p {
            margin: 8px 0;
            font-size: 16px;
          }
          .details strong {
            color: #2c3e50;
            font-weight: 600;
          }
          .footer {
            margin-top: 30px;
            font-size: 14px;
            color: #777;
          }
          a.back-btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 500;
            transition: background-color 0.3s;
          }
          a.back-btn:hover {
            background-color: #0056b3;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>User Registration Denied</h1>
          <p>The user registration request has been denied by the Super Admin.</p>
          <div class="details">
            <p><strong>Name:</strong> ${user.name}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Role:</strong> ${user.role}</p>
            <p><strong>Denial Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p><strong>Status:</strong> Denied</p>
          </div>
          <p class="footer">The user has been notified via email.</p>
          <a href="${API_URL}" class="back-btn">Return to Dashboard</a>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Super Admin Deny Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});

// User Removal Request
app.post('/removeUser', authenticate, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ error: 'Unauthorized' });
  try {
    const { userId } = req.body;
    const userToRemove = await User.findById(userId);
    if (!userToRemove) return res.status(404).json({ error: 'User not found' });

    const requestingUser = await User.findById(req.user.id);
    if (requestingUser.role === 'admin' && (userToRemove.role === 'admin' || userToRemove.role === 'superadmin')) {
      const superApproveToken = jwt.sign({ userId: userToRemove._id, action: 'remove_approve' }, process.env.JWT_SECRET, { expiresIn: '7d' });
      const superDenyToken = jwt.sign({ userId: userToRemove._id, action: 'remove_deny' }, process.env.JWT_SECRET, { expiresIn: '7d' });

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: superAdminEmails,
        subject: `User Removal Request for ${userToRemove.name}`,
        html: `
          <p>Admin ${requestingUser.name} requests to remove:</p>
          <p>Name: ${userToRemove.name}</p>
          <p>Email: ${userToRemove.email}</p>
          <p>Role: ${userToRemove.role}</p>
          <a href="${API_URL}/user/remove/approve/${superApproveToken}">Approve</a>
          <a href="${API_URL}/user/remove/deny/${superDenyToken}">Deny</a>
        `
      };
      await transporter.sendMail(mailOptions);
      res.send('Removal request sent to Super Admin');
    } else if (requestingUser.role === 'superadmin') {
      userToRemove.status = 'removed';
      await userToRemove.save();

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: userToRemove.email,
        subject: 'Your Account Has Been Removed',
        html: `
          <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2c3e50; text-align: center;">Account Removal Notification</h2>
            <p>Dear ${userToRemove.salutation || ''} ${userToRemove.name},</p>
            <p>We regret to inform you that your account with the <strong>Chemical Management System</strong> has been removed by the Super Admin on ${new Date().toLocaleDateString()}.</p>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0; background-color: #f9f9f9; border: 1px solid #ddd;">
              <tr style="background-color: #f2f2f2;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Name:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${userToRemove.name}</td>
              </tr>
              <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Email:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${userToRemove.email}</td>
              </tr>
              <tr style="background-color: #f2f2f2;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Role:</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">${userToRemove.role}</td>
              </tr>
            </table>
      
            <p>If you believe this action was taken in error or if you have any questions, please contact our support team at <a href="mailto:${process.env.EMAIL_USER}" style="color: #007bff; text-decoration: none;">${process.env.EMAIL_USER}</a>.</p>
            
            <p style="margin-top: 30px;">Sincerely,</p>
            <p><strong>Chemical Management System Team</strong><br>
            Automated Notification Service</p>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="font-size: 12px; color: #777; text-align: center;">This is an automated email. Please do not reply directly to this message.</p>
          </div>
        `,
      };
      await transporter.sendMail(mailOptions);
      res.send('User removed successfully');
    }
  } catch (error) {
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});




app.get('/user/remove/approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'remove_approve') return res.status(400).json({ error: 'Invalid token' });

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.status = 'removed';
    await user.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Account Removal Notification',
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #2c3e50; text-align: center;">Account Removal Notification</h2>
          <p>Dear ${user.name},</p>
          <p>We regret to inform you that your account with the Chemical Management System has been removed by the Super Admin. Below are the details of this action:</p>
          
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0; background-color: #f9f9f9; border: 1px solid #ddd;">
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Name:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${user.name}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Email:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${user.email}</td>
            </tr>
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Role:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${user.role}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Removal Date:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">${new Date().toLocaleDateString()}</td>
            </tr>
            <tr style="background-color: #f2f2f2;">
              <td style="padding: 10px; border: 1px solid #ddd;"><strong>Status:</strong></td>
              <td style="padding: 10px; border: 1px solid #ddd;">Removed</td>
            </tr>
          </table>

          <p>If you believe this action was taken in error or have any questions, please contact our support team at <a href="mailto:${process.env.EMAIL_USER}" style="color: #007bff; text-decoration: none;">${process.env.EMAIL_USER}</a>.</p>
          
          <p>Thank you for your understanding.</p>
          
          <p style="margin-top: 30px;">Best regards,</p>
          <p><strong>Chemical Management System</strong><br>
          Automated Notification Service</p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="font-size: 12px; color: #777; text-align: center;">This is an automated email. Please do not reply directly to this message.</p>
        </div>
      `
    };
    await transporter.sendMail(mailOptions);

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>User Removal Approved</title>
        <style>
          body {
            font-family: 'Arial', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f4f4f9;
          }
          .container {
            text-align: center;
            background-color: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 90%;
          }
          h1 {
            color: #dc3545;
            font-size: 28px;
            margin-bottom: 20px;
          }
          p {
            color: #444;
            font-size: 18px;
            margin: 10px 0;
          }
          .details {
            margin-top: 25px;
            text-align: left;
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #eee;
          }
          .details p {
            margin: 8px 0;
            font-size: 16px;
          }
          .details strong {
            color: #2c3e50;
            font-weight: 600;
          }
          .footer {
            margin-top: 30px;
            font-size: 14px;
            color: #777;
          }
          a.back-btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 500;
            transition: background-color 0.3s;
          }
          a.back-btn:hover {
            background-color: #0056b3;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>User Removal Approved</h1>
          <p>The user removal request has been successfully processed by the Super Admin.</p>
          <div class="details">
            <p><strong>Name:</strong> ${user.name}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Role:</strong> ${user.role}</p>
            <p><strong>Removal Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p><strong>Status:</strong> Removed</p>
          </div>
          <p class="footer">The user has been notified via email.</p>
          <a href="${API_URL}" class="back-btn">Return to Dashboard</a>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('User Removal Approval Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});

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
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
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
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
  try {
    const {
      chemicalName, chemicalType, type, phase, purity, quantityAvailable, unit, make, dateOfMFG, dateOfExp,
      purchase, purchaseDate, invoiceNumber, isAbsolute, isApproximately, rack
    } = req.body;

    if (!chemicalName || !phase || !quantityAvailable) {
      return res.status(400).json({ error: 'Chemical name, phase, and quantity available are required' });
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
      phase,
      purity,
      quantityAvailable: parseFloat(quantityAvailable),
      unit,
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


app.get('/getchemicals', authenticate, async (req, res) => {
  try {
    // Fetch all chemicals
    const chemicals = await Chemical.find().lean();

    // If the user is an admin, enrich the data with user usage info
    if (req.user.role === 'admin' && req.user.role === 'superadmin') {
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




app.post('/requestChemical', authenticate, async (req, res) => {
  try {
      const { chemicalId, requestedQuantity, requestedUnit } = req.body;
      if (!chemicalId || !requestedQuantity) return res.status(400).json({ error: 'Chemical ID and quantity required' });

      const quantity = parseFloat(requestedQuantity);
      if (isNaN(quantity) || quantity <= 0) return res.status(400).json({ error: 'Invalid quantity value' });

      const chemical = await Chemical.findOne({ chemicalId });
      if (!chemical) return res.status(404).json({ error: 'Chemical not found' });

      const requestUnit = requestedUnit || chemical.unit; // Default to chemical's unit if not provided
      if (chemical.unit !== requestUnit) {
          return res.status(400).json({ 
              error: `Unit mismatch: Requested in ${requestUnit}, but chemical is stored in ${chemical.unit}` 
          });
      }

      if (chemical.quantityAvailable < quantity) return res.status(400).json({ error: 'Not enough stock' });

      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      console.log(`Before update: ${chemical.quantityAvailable} ${chemical.unit}`);
      chemical.quantityAvailable -= quantity;
      await chemical.save();
      console.log(`After update: ${chemical.quantityAvailable} ${chemical.unit}`);

      const userChemical = new UserChemical({
          userId: req.user.id,
          chemicalId: chemical.chemicalId,
          chemicalName: chemical.chemicalName,
          quantityUsed: quantity,
          unit: chemical.unit,
          date: new Date(),
          name: user.name
      });
      await userChemical.save();

      res.status(200).json({
          message: 'Chemical issued successfully',
          updatedStock: chemical.quantityAvailable,
          unit: chemical.unit
      });
  } catch (error) {
      console.error('Request Chemical Error:', error.message);
      res.status(500).json({ error: 'Server Error', details: error.message });
  }
});


app.get('/getUserChemicals', authenticate, async (req, res) => {
  try {
      let userChemicals;
      if (req.user.role === 'admin' && req.user.role !== 'superadmin') {
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
// server.js (update this route)
app.get('/getUserDetails', authenticate, async (req, res) => {
  try {
      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json({
          name: user.name,
          email: user.email,
          role: user.role,
          salutation: user.salutation,
          designation: user.designation,
          department: user.department,
          contactNumber: user.contactNumber,
          joiningDate: user.joiningDate,
          status: user.status
      });
  } catch (error) {
      console.error('Get User Details Error:', error.message);
      res.status(500).json({ error: 'Server Error', details: error.message });
  }
});





app.put('/updateChemical/:chemicalId', authenticate, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
  try {
    const { chemicalId } = req.params;
    const { chemicalName, gramsAvailable, dateOfMFG, dateOfExp, purchase, purchaseDate, invoiceNumber, isAbsolute, isApproximately, rack } = req.body;

    console.log(`[PUT] Request received for chemicalId: "${chemicalId}"`);
    console.log(`[PUT] Request body: ${JSON.stringify(req.body)}`);

    const trimmedChemicalId = chemicalId.trim();
    const chemical = await Chemical.findOne({ chemicalId: trimmedChemicalId });
    if (!chemical) {
      console.log(`[PUT] No chemical found with chemicalId: "${trimmedChemicalId}"`);
      return res.status(404).json({ error: `Chemical with ID "${trimmedChemicalId}" not found` });
    }

    if (gramsAvailable === undefined || !dateOfMFG || !dateOfExp || !chemicalName || !rack) {
      return res.status(400).json({ error: 'Missing required fields (chemicalName, gramsAvailable, dateOfMFG, dateOfExp, rack)' });
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
        chemicalName: chemicalName.toUpperCase(),
        gramsAvailable: grams,
        dateOfMFG: mfgDate,
        dateOfExp: expDate,
        ...(purchaseValue !== undefined && { purchase: purchaseValue }),
        ...(purchaseDateValue && { purchaseDate: purchaseDateValue }),
        invoiceNumber: invoiceNumber || chemical.invoiceNumber,
        isAbsolute: isAbsolute || false,
        isApproximately: isApproximately || false,
        rack
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
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
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










// new scrap request

// POST /scrapRequest - Initial request goes to admins only
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

    const scrapRequest = new ScrapRequest({
      chemicalId,
      chemicalName: chemical.chemicalName,
      userName: user.name,
      userId: user._id,
      date: new Date(),
      status: 'pending',
      scrapPhotoPath: scrapPhoto.path,
    });
    await scrapRequest.save();

    const approveToken = jwt.sign(
      { chemicalId, action: 'approve', userId: req.user.id, requestId: scrapRequest._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    const denyToken = jwt.sign(
      { chemicalId, action: 'deny', userId: req.user.id, requestId: scrapRequest._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const approveLink = `${API_URL}/scrap/approve/${approveToken}`;
    const denyLink = `${API_URL}/scrap/deny/${denyToken}`;

    const { adminEmails } = await getAdminEmails();
    const baseUrl = process.env.BASE_URL || `${API_URL}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: adminEmails,
      subject: `Scrap Request Notification for ${chemical.chemicalName}`,
      html: `<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
  <!-- Logo Header -->
  <div style="text-align: center; margin-bottom: 25px;">
    <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
  </div>

  <!-- Title -->
  <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Scrap Request Notification</h2>

  <!-- Greeting and Intro -->
  <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear Admin,</p>
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">A scrap request has been submitted for your review:</p>

  <!-- Details Table -->
  <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">User Name</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.name}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical Name</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemical.chemicalName}</td>
    </tr>
    <tr style="background-color: #007367;">
      <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Request Date</td>
      <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
    </tr>
  </table>

  <!-- Action Prompt -->
  <p style="font-size: 15px; margin: 0 0 20px; color: #444;">Please review the scrap request for <strong>${chemical.chemicalName}</strong> by <strong>${user.name}</strong> and take action using the options below:</p>
  <div style="text-align: center; margin: 0 0 25px;">
    <a href="${approveLink}" 
       style="display: inline-block; padding: 12px 28px; background-color: #2ecc71; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
      Approve
    </a>
    <a href="${denyLink}" 
       style="display: inline-block; padding: 12px 28px; background-color: #e74c3c; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
      Deny
    </a>
  </div>

  <!-- Alternative Action -->
  <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Alternatively, you may manage this request via the <a href="${baseUrl}/dashboard" style="color: #2980b9; text-decoration: none; font-weight: 500;">CIMS Dashboard</a>.</p>

  <!-- Footer -->
  <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
    <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
    <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
    <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
    <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
      📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
      | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
    </p>
    <p style="font-size: 13px; margin: 0; color: #666;">
      <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
    </p>
  </div>

  <!-- Disclaimer -->
  <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
  <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
    This is an automated notification from CIMS. Please do not reply directly to this email. 
    For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
  </p>
</div>`, // Simplified for brevity
      attachments: [{ filename: scrapPhoto.originalname, path: scrapPhoto.path }],
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Scrap request with photo sent to admin successfully' });
  } catch (error) {
    console.error('Scrap Request Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});
// GET /scrap/approve/:token - Admin approval triggers superadmin notification
app.get('/scrap/approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'approve') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalId, userId, requestId } = decoded;
    const chemical = await Chemical.findOne({ chemicalId });
    const user = await User.findById(userId);
    if (!chemical || !user) return res.status(404).json({ error: 'Chemical or user not found' });

    // Update scrap request status to 'admin-approved'
    const scrapRequest = await ScrapRequest.findByIdAndUpdate(
      requestId,
      { status: 'admin-approved' },
      { new: true }
    );
    if (!scrapRequest) return res.status(404).json({ error: 'Scrap request not found' });

    // Generate tokens for superadmin approval/denial
    const superApproveToken = jwt.sign(
      { chemicalId, action: 'super-approve', userId, requestId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    const superDenyToken = jwt.sign(
      { chemicalId, action: 'super-deny', userId, requestId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const superApproveLink = `${API_URL}/scrap/super-approve/${superApproveToken}`;
    const superDenyLink = `${API_URL}/scrap/super-deny/${superDenyToken}`;

    const { superAdminEmails } = await getAdminEmails();
    const baseUrl = process.env.BASE_URL || `${API_URL}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: superAdminEmails,
      subject: `Final Approval Required: Scrap Request for ${chemical.chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Scrap Request - Final Approval Required</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear Super Admin,</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">An admin has approved the following scrap request. Please provide your final approval or denial:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">User Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.name}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemical.chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical ID</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalId}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Request Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date(scrapRequest.date).toLocaleDateString()}</td>
            </tr>
          </table>

          <!-- Action Prompt -->
          <p style="font-size: 15px; margin: 0 0 20px; color: #444;">Please review the attached photo and take action using the options below:</p>
          <div style="text-align: center; margin: 0 0 25px;">
            <a href="${superApproveLink}" 
               style="display: inline-block; padding: 12px 28px; background-color: #2ecc71; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
              Approve Scrap Request
            </a>
            <a href="${superDenyLink}" 
               style="display: inline-block; padding: 12px 28px; background-color: #e74c3c; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
              Deny Scrap Request
            </a>
          </div>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
        </div>
      `,
      attachments: [{
        filename: 'scrapPhoto.jpg', // Adjust filename as needed
        path: scrapRequest.scrapPhotoPath,
      }],
    };

    await transporter.sendMail(mailOptions);

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scrap Request - Admin Approved</title>
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
          <h1>Scrap Request - Admin Approved</h1>
          <p>The scrap request has been approved by an admin and sent to superadmin for final approval.</p>
          <div class="details">
            <p><strong>Chemical ID:</strong> ${chemicalId}</p>
            <p><strong>Chemical Name:</strong> ${chemical.chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Admin Approval Date:</strong> ${new Date().toLocaleDateString()}</p>
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

// GET /scrap/deny/:token - Admin denial notifies user
app.get('/scrap/deny/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'deny') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalId, userId, requestId } = decoded;
    const user = await User.findById(userId);
    const chemical = await Chemical.findOne({ chemicalId });
    if (!user || !chemical) return res.status(404).json({ error: 'User or chemical not found' });

    // Update scrap request status to 'denied'
    const scrapRequest = await ScrapRequest.findByIdAndUpdate(
      requestId,
      { status: 'denied' },
      { new: true }
    );
    if (!scrapRequest) return res.status(404).json({ error: 'Scrap request not found' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `Scrap Request Denied for ${chemical.chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Scrap Request Denial Notification</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.name || 'User'},</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Your scrap request has been reviewed and denied by the administrator:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical ID</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalId}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemical.chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denial Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Status</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denied</td>
            </tr>
          </table>

          <!-- Contact Prompt -->
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Please contact the admin team if you have questions.</p>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    // Clean up the uploaded photo if denied
    if (fs.existsSync(scrapRequest.scrapPhotoPath)) {
      fs.unlinkSync(scrapRequest.scrapPhotoPath);
    }

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
          <p>The scrap request has been denied by an admin.</p>
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

// GET /scrap/super-approve/:token - Superadmin final approval
app.get('/scrap/super-approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'super-approve') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalId, userId, requestId } = decoded;
    const chemical = await Chemical.findOne({ chemicalId });
    const user = await User.findById(userId);
    if (!chemical || !user) return res.status(404).json({ error: 'Chemical or user not found' });

    // Update scrap request status to 'approved'
    const scrapRequest = await ScrapRequest.findByIdAndUpdate(
      requestId,
      { status: 'approved' },
      { new: true }
    );
    if (!scrapRequest) return res.status(404).json({ error: 'Scrap request not found' });

    // Move to ScrapChemical collection and delete from Chemical
    const scrapChemical = new ScrapRequest({
      chemicalId,
      chemicalName: chemical.chemicalName,
      userName: user.name,
      date: new Date(),
      status: 'approved',
    });
    await scrapChemical.save();
    await Chemical.findOneAndDelete({ chemicalId });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `Scrap Request Approved for ${chemical.chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Scrap Request Approval Notification</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.name},</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Your request to scrap the following chemical has been fully approved by the superadmin:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical ID</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalId}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemical.chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Approval Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
            </tr>
          </table>

          <!-- Confirmation Message -->
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">The chemical has been removed from the inventory.</p>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Super Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    // Clean up the uploaded photo after approval
    if (fs.existsSync(scrapRequest.scrapPhotoPath)) {
      fs.unlinkSync(scrapRequest.scrapPhotoPath);
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scrap Request Fully Approved</title>
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
          <h1>Scrap Request Fully Approved</h1>
          <p>The scrap request has been fully approved by the superadmin.</p>
          <div class="details">
            <p><strong>Chemical ID:</strong> ${chemicalId}</p>
            <p><strong>Chemical Name:</strong> ${chemical.chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Final Approval Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The user has been notified via email.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Scrap Super Approve Error:', error.message);
    res.status(500).send(`Server Error: ${error.message}`);
  }
});

// GET /scrap/super-deny/:token - Superadmin denial notifies user
app.get('/scrap/super-deny/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'super-deny') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalId, userId, requestId } = decoded;
    const user = await User.findById(userId);
    const chemical = await Chemical.findOne({ chemicalId });
    if (!user || !chemical) return res.status(404).json({ error: 'User or chemical not found' });

    // Update scrap request status to 'denied'
    const scrapRequest = await ScrapRequest.findByIdAndUpdate(
      requestId,
      { status: 'denied' },
      { new: true }
    );
    if (!scrapRequest) return res.status(404).json({ error: 'Scrap request not found' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `Scrap Request Denied for ${chemical.chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Scrap Request Denial Notification</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.name || 'User'},</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Your scrap request has been reviewed and denied by the superadmin:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical ID</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalId}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemical.chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denial Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Status</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denied</td>
            </tr>
          </table>

          <!-- Contact Prompt -->
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Please contact the admin team if you have questions.</p>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Super Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    // Clean up the uploaded photo if denied
    if (fs.existsSync(scrapRequest.scrapPhotoPath)) {
      fs.unlinkSync(scrapRequest.scrapPhotoPath);
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scrap Request Denied by Superadmin</title>
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
          <h1>Scrap Request Denied by Superadmin</h1>
          <p>The scrap request has been denied by the superadmin.</p>
          <div class="details">
            <p><strong>Chemical ID:</strong> ${chemicalId}</p>
            <p><strong>Chemical Name:</strong> ${chemical.chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Denial Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The user has been notified via email.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Scrap Super Deny Error:', error.message);
    res.status(500).send('Server Error');
  }
});

// Keep the existing /getScrapChemicals endpoint unchanged
app.get('/getScrapChemicals', authenticate, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ error: 'Unauthorized: Admins only' });
  try {
    const scrapChemicals = await ScrapRequest.find().lean();
    res.json(scrapChemicals);
  } catch (error) {
    console.error('Get Scrap Chemicals Error:', error.message);
    res.status(500).json({ error: 'Server Error', details: error.message });
  }
});




// new 
app.post('/newChemicalRequest', authenticate, async (req, res) => {
  try {
    const { chemicalName } = req.body;
    if (!chemicalName) return res.status(400).json({ error: 'Chemical name required' });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Save the request to the database
    const newChemicalRequest = new NewChemicalRequest({
      chemicalName,
      userName: user.name,
      userId: user._id,
      date: new Date(),
      status: 'pending', // Initial status
    });
    await newChemicalRequest.save();

    // Generate JWT tokens for admin approval and denial
    const approveToken = jwt.sign(
      { action: 'approve', chemicalName, userId: user._id, requestId: newChemicalRequest._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    const denyToken = jwt.sign(
      { action: 'deny', chemicalName, userId: user._id, requestId: newChemicalRequest._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { adminEmails } = await getAdminEmails(); // Only admin emails
    const baseUrl = process.env.BASE_URL || `${API_URL}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: adminEmails, // Send only to admins
      subject: `New Chemical Request from ${user.name} - ${chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">New Chemical Request Notification</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear Admin,</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">A new chemical request has been submitted for addition to the inventory:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">User Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.name}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Requested Chemical</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Request Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
            </tr>
          </table>

          <!-- Action Prompt -->
          <p style="font-size: 15px; margin: 0 0 20px; color: #444;">Please review and take action using the options below:</p>
          <div style="text-align: center; margin: 0 0 25px;">
            <a href="${baseUrl}/newChemical/approve/${approveToken}" 
               style="display: inline-block; padding: 12px 28px; background-color: #2ecc71; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
              Approve
            </a>
            <a href="${baseUrl}/newChemical/deny/${denyToken}" 
               style="display: inline-block; padding: 12px 28px; background-color: #e74c3c; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
              Deny
            </a>
          </div>

          <!-- Alternative Action -->
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Alternatively, you may manage this request via the <a href="${baseUrl}/dashboard" style="color: #2980b9; text-decoration: none; font-weight: 500;">CIMS Dashboard</a>.</p>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
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

// GET /newChemical/approve/:token - Admin approval triggers super admin notification
app.get('/newChemical/approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'approve') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalName, userId, requestId } = decoded;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Update request status to "admin-approved" (pending super admin approval)
    const request = await NewChemicalRequest.findByIdAndUpdate(
      requestId,
      { status: 'admin-approved' },
      { new: true }
    );
    if (!request) return res.status(404).json({ error: 'Request not found' });

    // Generate tokens for super admin approval/denial
    const superApproveToken = jwt.sign(
      { action: 'super-approve', chemicalName, userId, requestId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    const superDenyToken = jwt.sign(
      { action: 'super-deny', chemicalName, userId, requestId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { superAdminEmails } = await getAdminEmails();
    const baseUrl = process.env.BASE_URL || `${API_URL}`;

    // Notify super admins for final approval
    const superAdminMailOptions = {
      from: process.env.EMAIL_USER,
      to: superAdminEmails,
      subject: `Final Approval Required: New Chemical Request - ${chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">Final Approval Required - New Chemical Request</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear Super Admin,</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">An admin has approved the following new chemical request. Please provide your final approval or denial:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">User Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${user.name}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Requested Chemical</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Request Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date(request.date).toLocaleDateString()}</td>
            </tr>
          </table>

          <!-- Action Prompt -->
          <p style="font-size: 15px; margin: 0 0 20px; color: #444;">Please take one of the following actions:</p>
          <div style="text-align: center; margin: 0 0 25px;">
            <a href="${baseUrl}/newChemical/super-approve/${superApproveToken}" 
               style="display: inline-block; padding: 12px 28px; background-color: #2ecc71; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
              Approve
            </a>
            <a href="${baseUrl}/newChemical/super-deny/${superDenyToken}" 
               style="display: inline-block; padding: 12px 28px; background-color: #e74c3c; color: #ffffff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; margin: 0 8px; transition: background-color 0.3s;">
              Deny
            </a>
          </div>

          <!-- Alternative Action -->
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Alternatively, you may manage this request via the <a href="${baseUrl}/dashboard" style="color: #2980b9; text-decoration: none; font-weight: 500;">CIMS Dashboard</a>.</p>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
        </div>
      `,
    };

    await transporter.sendMail(superAdminMailOptions);

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Chemical Request - Admin Approved</title>
        <style>
          body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f4; }
          .container { text-align: center; background-color: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
          h1 { color: #2ecc71; }
          p { color: #333; font-size: 18px; }
          .details { margin-top: 20px; text-align: left; }
          .details strong { color: #2c3e50; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>New Chemical Request - Admin Approved</h1>
          <p>The request has been approved by an admin and sent to super admins for final approval.</p>
          <div class="details">
            <p><strong>Chemical Name:</strong> ${chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Admin Approval Date:</strong> ${new Date().toLocaleDateString()}</p>
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

// GET /newChemical/super-approve/:token - Super admin final approval
app.get('/newChemical/super-approve/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'super-approve') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalName, userId, requestId } = decoded;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Update request status to fully approved
    const request = await NewChemicalRequest.findByIdAndUpdate(
      requestId,
      { status: 'approved' },
      { new: true }
    );
    if (!request) return res.status(404).json({ error: 'Request not found' });

    // Notify the user
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `New Chemical Request Approved for ${chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">New Chemical Request Approval Notification</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.name},</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Your request for a new chemical has been fully approved:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Final Approval Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
            </tr>
          </table>

          <!-- Confirmation Message -->
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">The chemical will be added to the inventory soon.</p>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Super Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Chemical Request Fully Approved</title>
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
          <h1>New Chemical Request Fully Approved</h1>
          <p>The request has been fully approved by a super admin.</p>
          <div class="details">
            <p><strong>Chemical Name:</strong> ${chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Final Approval Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The user has been notified via email.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('New Chemical Super Approve Error:', error.message);
    res.status(500).send('Server Error');
  }
});

// GET /newChemical/deny/:token - Admin denial
app.get('/newChemical/deny/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'deny') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalName, userId, requestId } = decoded;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Update the request status
    const request = await NewChemicalRequest.findByIdAndUpdate(
      requestId,
      { status: 'denied' },
      { new: true }
    );
    if (!request) return res.status(404).json({ error: 'Request not found' });

    // Notify the user
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `New Chemical Request Denied for ${chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">New Chemical Request Denial Notification</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.name || 'User'},</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Your request for a new chemical has been denied:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denial Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
            </tr>
          </table>

          <!-- Contact Prompt -->
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Contact the admin team for more information.</p>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

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
          <p>The request has been denied by an admin.</p>
          <div class="details">
            <p><strong>Chemical Name:</strong> ${chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Denial Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The user has been notified via email.</p>
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


app.get('/newChemical/super-deny/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.action !== 'super-deny') return res.status(400).json({ error: 'Invalid token' });

    const { chemicalName, userId, requestId } = decoded;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Update request status to 'denied'
    const request = await NewChemicalRequest.findByIdAndUpdate(
      requestId,
      { status: 'denied' },
      { new: true }
    );
    if (!request) return res.status(404).json({ error: 'Request not found' });

    // Notify the user
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `New Chemical Request Denied for ${chemicalName}`,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 25px; background-color: rgb(255, 255, 255); border-radius: 10px; box-shadow: 0 4px 12px rgb(228, 228, 228);">
          <!-- Logo Header -->
          <div style="text-align: center; margin-bottom: 25px;">
            <img src="https://res.cloudinary.com/dcggiwav8/image/upload/v1742631887/Alchemira/dowh0fklo7hp9zc4iatt.png" alt="Alchemiera Logo" style="width: 200px; height: auto;" />
          </div>

          <!-- Title -->
          <h2 style="color: #003d36; font-size: 24px; margin: 0 0 20px; font-weight: 600; text-align: center;">New Chemical Request Denial Notification</h2>

          <!-- Greeting and Intro -->
          <p style="font-size: 15px; margin: 0 0 10px; color: #444;">Dear ${user.name || 'User'},</p>
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Your request for a new chemical has been denied by the superadmin:</p>

          <!-- Details Table -->
          <table style="width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 25px; background-color: #007367; border-radius: 10px; box-shadow: 0 1px 3px rgba(255, 255, 255, 0.28);">
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Chemical Name</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${chemicalName}</td>
            </tr>
            <tr style="background-color: #007367;">
              <td style="padding: 12px 15px; font-weight: 600; font-size: 14px; width: 40%; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">Denial Date</td>
              <td style="padding: 12px 15px; font-size: 14px; border-bottom: 1px solid #f0e0c1; color: #f0e0c1;">${new Date().toLocaleDateString()}</td>
            </tr>
          </table>

          <!-- Contact Prompt -->
          <p style="font-size: 15px; margin: 0 0 25px; color: #444;">Contact the admin team for more information.</p>

          <!-- Footer -->
          <div style="text-align: left; border-top: 1px solid #003d36; padding-top: 20px; margin-top: 20px;">
            <p style="font-size: 14px; margin: 0 0 5px; color: #555;">Best regards,</p>
            <p style="font-size: 15px; margin: 0 0 5px; font-weight: 600; color: #333;">Super Admin</p>
            <p style="font-size: 16px; margin: 0 0 8px; font-weight: 600; color: #f0e0c1;">CIMS – Chemical Inventory Management System</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">Powered by Alchemiera Bioelectronics India Private Limited</p>
            <p style="font-size: 13px; margin: 0 0 5px; color: #666;">
              📧 <a href="mailto:alchemierabioelectronics@gmail.com" style="color: rgb(192, 230, 255); text-decoration: none;">alchemierabioelectronics@gmail.com</a> 
              | 📞 +91 9191080 48750 | 📞 +91 99001 63967 | 📞 +91 9080 856131
            </p>
            <p style="font-size: 13px; margin: 0; color: #666;">
              <a href="https://www.indiumlaboratory.com/" style="color: rgb(159, 217, 255); text-decoration: none;">🌐 www.indiumlaboratory.com</a>
            </p>
          </div>

          <!-- Disclaimer -->
          <hr style="border: none; border-top: 1px solid rgb(0, 0, 0); margin: 25px 0;" />
          <p style="font-size: 11px; color: #888; text-align: left; margin: 0; line-height: 1.4;">
            This is an automated notification from CIMS. Please do not reply directly to this email. 
            For assistance, contact <a href="mailto:${process.env.EMAIL_USER}" style="color: rgb(152, 214, 255); text-decoration: none;">${process.env.EMAIL_USER}</a>.
          </p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Chemical Request Denied by Superadmin</title>
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
          <h1>New Chemical Request Denied by Superadmin</h1>
          <p>The request has been denied by the superadmin.</p>
          <div class="details">
            <p><strong>Chemical Name:</strong> ${chemicalName}</p>
            <p><strong>Requested by:</strong> ${user.name}</p>
            <p><strong>Denial Date:</strong> ${new Date().toLocaleDateString()}</p>
            <p>The user has been notified via email.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('New Chemical Super Deny Error:', error.message);
    res.status(500).send('Server Error');
  }
});





app.get('/getNewChemicalRequests', authenticate, async (req, res) => {
  try {
    const requests = await NewChemicalRequest.find({ status: 'pending' }); // Only pending requests
    res.status(200).json(requests);
  } catch (error) {
    console.error('Get New Chemical Requests Error:', error.message);
    res.status(500).json({ error: 'Server Error' });
  }
});



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
