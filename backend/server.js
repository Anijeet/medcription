const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://Sbrain:anijeet3@cluster0.myn96bp.mongodb.net/doctor_management';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// User Schema (Admin)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['admin'], default: 'admin' },
  createdAt: { type: Date, default: Date.now }
});

// Tenant Schema (Company/Hospital)
const tenantSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  companyName: { type: String, required: true },
  address: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  description: { type: String },
  createdAt: { type: Date, default: Date.now }
});

// Tenant User Schema (Doctor)
const tenantUserSchema = new mongoose.Schema({
  tenant_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  specialization: { type: String, required: true },
  phone: { type: String, required: true },
  qualification: { type: String, required: true },
  experience: { type: Number, required: true },
  role: { type: String, enum: ['doctor'], default: 'doctor' },
  createdAt: { type: Date, default: Date.now }
});

// Patient Schema
const patientSchema = new mongoose.Schema({
  tenant_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true },
  tenant_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'TenantUser', required: true },
  name: { type: String, required: true },
  age: { type: Number, required: true },
  gender: { type: String, enum: ['Male', 'Female', 'Other'], required: true },
  phone: { type: String, required: true },
  email: { type: String },
  address: { type: String, required: true },
  bloodGroup: { type: String, required: true },
  medicalHistory: { type: String },
  prescriptions: [{
    date: { type: Date, default: Date.now },
    pdfPath: { type: String, required: true },
    name: { type: String, required: true }
  }],
  createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Tenant = mongoose.model('Tenant', tenantSchema);
const TenantUser = mongoose.model('TenantUser', tenantUserSchema);
const Patient = mongoose.model('Patient', patientSchema);

// JWT Secret
const JWT_SECRET = 'your_jwt_secret_key_here';

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes

// Admin Registration
app.post('/api/admin/register', async (req, res) => {
  try {
    const { email, password, name, companyName, address, phone, companyEmail, description } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create admin user
    const user = new User({
      email,
      password: hashedPassword,
      name,
      role: 'admin'
    });

    const savedUser = await user.save();

    // Create tenant (company)
    const tenant = new Tenant({
      user_id: savedUser._id,
      companyName,
      address,
      phone,
      email: companyEmail,
      description
    });

    await tenant.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: savedUser._id, role: 'admin', tenantId: tenant._id },
      JWT_SECRET
    );

    res.status(201).json({
      message: 'Admin registered successfully',
      token,
      user: {
        id: savedUser._id,
        email: savedUser.email,
        name: savedUser.name,
        role: savedUser.role,
        tenantId: tenant._id
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error registering admin', error: error.message });
  }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Find tenant
    const tenant = await Tenant.findOne({ user_id: user._id });

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: 'admin', tenantId: tenant._id },
      JWT_SECRET
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        tenantId: tenant._id
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// Doctor Login
app.post('/api/doctor/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find doctor
    const doctor = await TenantUser.findOne({ email });
    if (!doctor) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, doctor.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: doctor._id, role: 'doctor', tenantId: doctor.tenant_id },
      JWT_SECRET
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: doctor._id,
        email: doctor.email,
        name: doctor.name,
        role: doctor.role,
        tenantId: doctor.tenant_id
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// Get Company Details
app.get('/api/company/:tenantId', authenticateToken, async (req, res) => {
  try {
    const tenant = await Tenant.findById(req.params.tenantId);
    if (!tenant) {
      return res.status(404).json({ message: 'Company not found' });
    }
    res.json(tenant);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching company details', error: error.message });
  }
});

// Update Company Details
app.put('/api/company/:tenantId', authenticateToken, async (req, res) => {
  try {
    const { companyName, address, phone, email, description } = req.body;
    
    const tenant = await Tenant.findByIdAndUpdate(
      req.params.tenantId,
      { companyName, address, phone, email, description },
      { new: true }
    );

    if (!tenant) {
      return res.status(404).json({ message: 'Company not found' });
    }

    res.json({ message: 'Company updated successfully', tenant });
  } catch (error) {
    res.status(500).json({ message: 'Error updating company', error: error.message });
  }
});

// Create Doctor
app.post('/api/doctors', authenticateToken, async (req, res) => {
  try {
    const { name, email, specialization, phone, qualification, experience, password } = req.body;

    // Check if doctor already exists
    const existingDoctor = await TenantUser.findOne({ email });
    if (existingDoctor) {
      return res.status(400).json({ message: 'Doctor with this email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const doctor = new TenantUser({
      tenant_id: req.user.tenantId,
      name,
      email,
      specialization,
      phone,
      qualification,
      experience,
      password: hashedPassword
    });

    await doctor.save();
    res.status(201).json({ message: 'Doctor created successfully', doctor });
  } catch (error) {
    res.status(500).json({ message: 'Error creating doctor', error: error.message });
  }
});

// Get All Doctors
app.get('/api/doctors', authenticateToken, async (req, res) => {
  try {
    const doctors = await TenantUser.find({ tenant_id: req.user.tenantId })
      .select('-password');
    res.json(doctors);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching doctors', error: error.message });
  }
});

// Update Doctor
app.put('/api/doctors/:id', authenticateToken, async (req, res) => {
  try {
    const { name, email, specialization, phone, qualification, experience } = req.body;
    
    const doctor = await TenantUser.findByIdAndUpdate(
      req.params.id,
      { name, email, specialization, phone, qualification, experience },
      { new: true }
    ).select('-password');

    if (!doctor) {
      return res.status(404).json({ message: 'Doctor not found' });
    }

    res.json({ message: 'Doctor updated successfully', doctor });
  } catch (error) {
    res.status(500).json({ message: 'Error updating doctor', error: error.message });
  }
});

// Delete Doctor
app.delete('/api/doctors/:id', authenticateToken, async (req, res) => {
  try {
    const doctor = await TenantUser.findByIdAndDelete(req.params.id);
    if (!doctor) {
      return res.status(404).json({ message: 'Doctor not found' });
    }
    res.json({ message: 'Doctor deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting doctor', error: error.message });
  }
});

// Create Patient
app.post('/api/patients', authenticateToken, async (req, res) => {
  try {
    const { name, age, gender, phone, email, address, bloodGroup, medicalHistory, doctorId } = req.body;

    const patient = new Patient({
      tenant_id: req.user.tenantId,
      tenant_user_id: doctorId || req.user.userId,
      name,
      age,
      gender,
      phone,
      email,
      address,
      bloodGroup,
      medicalHistory
    });

    await patient.save();
    res.status(201).json({ message: 'Patient created successfully', patient });
  } catch (error) {
    res.status(500).json({ message: 'Error creating patient', error: error.message });
  }
});

// Get All Patients (Admin sees all, Doctor sees only their patients)
app.get('/api/patients', authenticateToken, async (req, res) => {
  try {
    let query = { tenant_id: req.user.tenantId };
    
    // If user is a doctor, only show their patients
    if (req.user.role === 'doctor') {
      query.tenant_user_id = req.user.userId;
    }

    const patients = await Patient.find(query)
      .populate('tenant_user_id', 'name specialization')
      .sort({ createdAt: -1 });

    res.json(patients);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching patients', error: error.message });
  }
});

// Get Single Patient
app.get('/api/patients/:id', authenticateToken, async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id)
      .populate('tenant_user_id', 'name specialization');
    
    if (!patient) {
      return res.status(404).json({ message: 'Patient not found' });
    }

    res.json(patient);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching patient', error: error.message });
  }
});

// Update Patient
app.put('/api/patients/:id', authenticateToken, async (req, res) => {
  try {
    const { name, age, gender, phone, email, address, bloodGroup, medicalHistory } = req.body;
    
    const patient = await Patient.findByIdAndUpdate(
      req.params.id,
      { name, age, gender, phone, email, address, bloodGroup, medicalHistory },
      { new: true }
    );

    if (!patient) {
      return res.status(404).json({ message: 'Patient not found' });
    }

    res.json({ message: 'Patient updated successfully', patient });
  } catch (error) {
    res.status(500).json({ message: 'Error updating patient', error: error.message });
  }
});

// Add Prescription (Upload PDF)
app.post('/api/patients/:id/prescriptions', authenticateToken, upload.single('prescription'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const patient = await Patient.findById(req.params.id);
    if (!patient) {
      return res.status(404).json({ message: 'Patient not found' });
    }

    // Generate prescription name
    const prescriptionNumber = patient.prescriptions.length + 1;
    const date = new Date().toLocaleDateString();
    const prescriptionName = `${date}-prescription-${prescriptionNumber}`;

    // Add prescription to patient
    patient.prescriptions.push({
      date: new Date(),
      pdfPath: req.file.path,
      name: prescriptionName
    });

    await patient.save();

    res.json({ 
      message: 'Prescription added successfully', 
      prescription: {
        name: prescriptionName,
        pdfPath: req.file.path,
        date: new Date()
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error adding prescription', error: error.message });
  }
});

// Get Prescription PDF
app.get('/api/prescriptions/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', filename);
  res.sendFile(filePath);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});