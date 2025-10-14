const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const app = express();
const PORT = process.env.PORT || 5000;
require("dotenv").config();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// ✅ Initialize Firebase Admin SDK
try {
  let serviceAccount;
  
  if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
    console.log('📦 Loading Firebase credentials from environment variable');
    const decoded = Buffer.from(
      process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 
      'base64'
    ).toString('utf-8');
    serviceAccount = JSON.parse(decoded);
    console.log('✅ Firebase credentials decoded successfully');
  } else {
    console.log('📁 Loading Firebase credentials from local file');
    serviceAccount = require('./serviceAccountKey.json');
  }
  
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  
  console.log('✅ Firebase Admin initialized successfully');
  console.log('📧 Service account:', serviceAccount.client_email);
  
} catch (error) {
  console.error('❌ Error initializing Firebase Admin:', error.message);
}

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --------------------------
// Schemas
// --------------------------
const leadSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  user_id: mongoose.Schema.Types.ObjectId,  // ✅ Changed to ObjectId

  customer_name: String,
  name: String,
  lead_name: String,

  customer_phone: String,
  phone: String,
  mobile: String,
  contact: String,

  customer_email: String,
  email: String,

  location: String,
  city: String,
  address: String,

  requirement: String,
  requirements: String,
  description: String,
  details: String,
  service: String,

  status: String,
  lead_status: String,
  priority: String,

  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
}, { timestamps: true });

const Lead = mongoose.model("Lead", leadSchema);

const formSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, required: true },
  requirement: { type: String, required: true },
  location: { type: String, required: true },
  status: { type: String, required: true },
}, { timestamps: true });

const Form = mongoose.model("Form", formSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  fcm_token: { type: String, default: null },
  fcm_platform: { type: String, default: null },
  fcm_updated_at: { type: Date, default: null }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

const User = mongoose.model("User", userSchema);

// --------------------------
// Helper Function: Send FCM Notification
// --------------------------
async function sendFCMNotification(userId, leadData) {
  try {
    console.log('');
    console.log('═══════════════════════════════════');
    console.log('📱 FCM NOTIFICATION PROCESS START');
    console.log('═══════════════════════════════════');
    console.log('1️⃣ Input User ID:', userId);
    console.log('2️⃣ User ID Type:', typeof userId);
    
    if (!userId) {
      console.error('❌ User ID is null or undefined');
      return { success: false, error: 'User ID is required' };
    }
    
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      console.error('❌ Invalid MongoDB ObjectId format:', userId);
      return { success: false, error: 'Invalid user ID format' };
    }
    
    console.log('3️⃣ Searching for user...');
    const user = await User.findById(userId);
    
    if (!user) {
      console.error('❌ User not found in database');
      return { success: false, error: 'User not found' };
    }
    
    console.log('4️⃣ ✅ User found:', user.username);
    console.log('5️⃣ Checking FCM token...');
    
    if (!user.fcm_token) {
      console.error('❌ User has no FCM token');
      return { success: false, error: 'No FCM token for this user' };
    }
    
    console.log('6️⃣ ✅ FCM Token exists');
    console.log('   Preview:', user.fcm_token.substring(0, 30) + '...');
    
    const message = {
      token: user.fcm_token,
      data: {
        type: 'new_lead',
        lead_id: String(leadData.id || leadData._id),
        lead_name: leadData.name || leadData.lead_name || leadData.customer_name || 'New Lead',
        lead_service: leadData.service || leadData.requirement || 'Service inquiry',
        lead_city: leadData.city || leadData.location || '',
        lead_mobile: leadData.mobile || leadData.phone || leadData.customer_phone || ''
      },
      android: {
        priority: 'high',
        notification: {
          channelId: 'lead_notifications'
        }
      }
    };
    
    console.log('7️⃣ Message prepared:');
    console.log('   Lead:', message.data.lead_name);
    console.log('   Service:', message.data.lead_service);
    
    console.log('8️⃣ Sending FCM message...');
    const response = await admin.messaging().send(message);
    
    console.log('9️⃣ ✅ SUCCESS! Notification sent');
    console.log('   Response:', response);
    console.log('═══════════════════════════════════');
    console.log('');
    
    return { success: true, response };
    
  } catch (error) {
    console.error('');
    console.error('═══════════════════════════════════');
    console.error('❌ FCM ERROR');
    console.error('═══════════════════════════════════');
    console.error('Code:', error.code);
    console.error('Message:', error.message);
    console.error('═══════════════════════════════════');
    console.error('');
    return { success: false, error: error.message, code: error.code };
  }
}

// --------------------------
// Routes
// --------------------------

app.get("/", (req, res) => {
  res.json({
    message: "Ekarigar Sales API is running",
    firebase: admin.apps.length > 0 ? "✅ Connected" : "❌ Not connected",
    timestamp: new Date().toISOString()
  });
});

// ✅ DEBUG: List all users
app.get('/api/debug/users', async (req, res) => {
  try {
    const users = await User.find({}, { 
      username: 1, 
      _id: 1, 
      fcm_token: 1,
      fcm_updated_at: 1
    });
    
    res.json({
      total: users.length,
      users: users.map(u => ({
        id: u._id,
        username: u.username,
        has_fcm_token: !!u.fcm_token,
        fcm_token_preview: u.fcm_token ? u.fcm_token.substring(0, 30) + '...' : null,
        fcm_updated_at: u.fcm_updated_at
      }))
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Save FCM Token
app.post('/api/save-fcm-token', async (req, res) => {
  try {
    const { user_id, fcm_token, platform } = req.body;
    
    if (!user_id || !fcm_token) {
      return res.status(400).json({
        success: false,
        message: 'user_id and fcm_token are required'
      });
    }
    
    console.log('💾 Saving FCM token for user:', user_id);
    
    const user = await User.findById(user_id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    user.fcm_token = fcm_token;
    user.fcm_platform = platform || 'android';
    user.fcm_updated_at = new Date();
    await user.save();
    
    console.log('✅ FCM token saved successfully for:', user.username);
    
    res.json({
      success: true,
      message: 'FCM token saved successfully'
    });
    
  } catch (error) {
    console.error('❌ Error saving FCM token:', error);
    res.status(500).json({
      success: false,
      message: 'Error saving FCM token',
      error: error.message
    });
  }
});

// Form Routes
app.post("/api/form", async (req, res) => {
  try {
    const { name, phone, requirement, location, status } = req.body;
    if (!name || !phone || !requirement || !location || !status) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const newForm = new Form({ name, phone, requirement, location, status });
    await newForm.save();
    res.status(201).json({ message: "Form submitted successfully", data: newForm });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/form", async (req, res) => {
  try {
    const forms = await Form.find().sort({ createdAt: -1 });
    res.status(200).json({ data: forms });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ UPDATED: Add Lead with Auto User Assignment
app.post('/api/addLeadsByUserId', async (req, res) => {
  try {
    console.log('');
    console.log('═══════════════════════════════════');
    console.log('🆕 NEW LEAD CREATION');
    console.log('═══════════════════════════════════');
    console.log('📦 Request body:', JSON.stringify(req.body, null, 2));
    
    // ✅ If user_id missing, assign first user with FCM token
    if (!req.body.user_id) {
      console.warn('⚠️ user_id missing, searching for user with FCM token...');
      
      // Find first user with FCM token
      const user = await User.findOne({ fcm_token: { $ne: null } }).sort({ fcm_updated_at: -1 });
      
      if (user) {
        req.body.user_id = user._id;
        console.log('✅ Auto-assigned to user:', user.username);
        console.log('   User ID:', user._id);
        console.log('   Has FCM token:', !!user.fcm_token);
      } else {
        console.error('❌ No user with FCM token found!');
        console.log('💡 Available users:');
        const allUsers = await User.find({}, { username: 1, _id: 1, fcm_token: 1 });
        allUsers.forEach(u => {
          console.log(`   - ${u.username} (ID: ${u._id}, Token: ${u.fcm_token ? 'YES' : 'NO'})`);
        });
      }
    } else {
      console.log('✅ user_id provided:', req.body.user_id);
    }
    
    const lead = new Lead(req.body);
    await lead.save();
    
    console.log('✅ Lead saved successfully');
    console.log('   Lead ID:', lead.id);
    console.log('   Assigned to user ID:', lead.user_id);
    console.log('═══════════════════════════════════');
    
    // Send notification
    if (lead.user_id) {
      console.log('📢 Sending notification...');
      const notificationResult = await sendFCMNotification(lead.user_id, lead);
      
      res.status(201).json({
        success: true,
        message: 'Lead added successfully',
        data: lead,
        notification_sent: notificationResult.success,
        notification_info: notificationResult
      });
    } else {
      console.warn('⚠️ No user assigned, notification not sent');
      res.status(201).json({
        success: true,
        message: 'Lead added but no user assigned',
        data: lead,
        notification_sent: false,
        error: 'No user_id available'
      });
    }
    
  } catch (error) {
    console.error('');
    console.error('═══════════════════════════════════');
    console.error('❌ ERROR ADDING LEAD');
    console.error('═══════════════════════════════════');
    console.error('Message:', error.message);
    console.error('Stack:', error.stack);
    console.error('═══════════════════════════════════');
    console.error('');
    
    res.status(500).json({
      success: false,
      message: 'Error adding lead',
      error: error.message
    });
  }
});

// Get Leads
app.post('/api/getLeadsByUserId', async (req, res) => {
  try {
    const { page = 1, limit = 10, user_id } = req.body;

    const query = {};
    if (user_id) {
      query.user_id = user_id;
    }

    const total = await Lead.countDocuments(query);
    const leads = await Lead.find(query)
      .sort({ created_at: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.status(200).json({
      status: true,
      leads: leads,
      total,
      page,
      perPage: limit,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving leads',
      error: error.message
    });
  }
});

app.get('/api/getLeadsByUserId', async (req, res) => {
  try {
    const leads = await Lead.find();
    res.status(200).json({ success: true, data: leads });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error retrieving leads',
      error: error.message
    });
  }
});

app.get('/api/getLeadsByUserId/:id', async (req, res) => {
  try {
    const lead = await Lead.findOne({ id: req.params.id });
    if (!lead) return res.status(404).json({
      success: false,
      message: 'Lead not found'
    });
    res.status(200).json({ success: true, data: lead });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error retrieving lead',
      error: error.message
    });
  }
});

// User Routes
app.post('/api/app-add', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        status: false,
        message: 'Username and password are required'
      });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({
        status: false,
        message: 'Username already exists'
      });
    }

    const user = new User({ username, password });
    await user.save();

    res.status(201).json({
      status: true,
      message: 'User added successfully',
      user: { id: user._id, username: user.username }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: false,
      message: 'Server error',
      error: error.message
    });
  }
});

app.post('/api/app-login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        status: false,
        message: 'Username and password are required'
      });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({
        status: false,
        message: 'Invalid username or password'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        status: false,
        message: 'Invalid username or password'
      });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '24h' }
    );

    res.status(200).json({
      status: true,
      message: 'Login successful',
      user: { id: user._id, username: user.username },
      token
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: false,
      message: 'Server error',
      error: error.message
    });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`\n🚀 Server running on port ${PORT}`);
  console.log(`📱 Firebase: ${admin.apps.length > 0 ? '✅ Initialized' : '❌ Not initialized'}`);
  console.log(`🔗 API: http://localhost:${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}\n`);
});
