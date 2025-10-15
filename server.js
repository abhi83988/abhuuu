const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

// --------------------------
// Firebase Admin Initialization
// --------------------------
try {
  let serviceAccount;
  if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
    const decoded = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf-8');
    serviceAccount = JSON.parse(decoded);
  } else {
    serviceAccount = require("./serviceAccountKey.json");
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });

  console.log("✅ Firebase Admin initialized");
} catch (error) {
  console.error("❌ Firebase initialization error:", error.message);
}

// --------------------------
// MongoDB Connection
// --------------------------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// Fix index issue on startup
mongoose.connection.once('open', async () => {
  console.log("🔧 Checking for problematic indexes...");
  try {
    const Lead = mongoose.model("Lead");
    await Lead.collection.dropIndex("id_1");
    console.log("✅ Dropped id_1 index");
  } catch (error) {
    console.log("ℹ️ Index id_1 not found (OK)");
  }
});

// --------------------------
// Schemas - FIXED VERSION
// --------------------------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  fcm_token: { type: String, default: null },
  device_type: { type: String, default: "android" },
  fcm_updated_at: { type: Date, default: null }
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model("User", userSchema);

// ✅ FIXED LEAD SCHEMA - NO 'id' FIELD
const leadSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  customer_name: { 
    type: String, 
    required: true 
  },
  customer_phone: { 
    type: String 
  },
  requirement: { 
    type: String 
  },
  city: { 
    type: String 
  },
  status: { 
    type: String, 
    default: 'New Lead',
    enum: ['New Lead', 'Cold', 'Warm', 'Hot', 'Converted']
  }
}, { 
  timestamps: true  // Automatically adds createdAt & updatedAt
});

const Lead = mongoose.model("Lead", leadSchema);

// --------------------------
// Helper: Send FCM Notification
// --------------------------
async function sendFCMNotification(userId, leadData) {
  try {
    const user = await User.findById(userId);
    if (!user || !user.fcm_token) {
      console.warn("❌ No FCM token for user");
      return { status: false, message: "No FCM token" };
    }

    const message = {
      token: user.fcm_token,
      notification: {
        title: "New Lead Added",
        body: `${leadData.customer_name || "Customer"} - ${leadData.requirement || "Requirement"}`
      },
      data: {
        type: "new_lead",
        lead_id: String(leadData._id),
        lead_name: leadData.customer_name || "",
        requirement: leadData.requirement || "",
        city: leadData.city || ""
      },
      android: {
        priority: "high",
        notification: { channelId: "lead_notifications" }
      }
    };

    const response = await admin.messaging().send(message);
    console.log("✅ Notification sent:", response);

    return { status: true, message: "Notification sent", response };
  } catch (error) {
    console.error("❌ FCM error:", error.message);
    return { status: false, message: error.message };
  }
}

// --------------------------
// Routes
// --------------------------
app.get("/", (req, res) => {
  res.json({ message: "Ekarigar Sales API running 🚀" });
});

// --------------------------
// 🔹 Create User
// --------------------------
app.post("/api/app-add", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ status: false, message: "Username & password required" });

    const existing = await User.findOne({ username });
    if (existing)
      return res.status(400).json({ status: false, message: "Username already exists" });

    const user = new User({ username, password });
    await user.save();

    res.json({
      status: true,
      message: "User added successfully",
      user: { id: user._id, username: user.username }
    });
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// --------------------------
// 🔹 Login (and optionally save FCM token)
// --------------------------
app.post("/api/app-login", async (req, res) => {
  try {
    const { username, password, fcm_token, device_type } = req.body;
    const user = await User.findOne({ username });

    if (!user)
      return res.status(401).json({ status: false, message: "Invalid username or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ status: false, message: "Invalid username or password" });

    // ✅ Auto-save FCM token if provided
    if (fcm_token) {
      user.fcm_token = fcm_token;
      user.device_type = device_type || "android";
      user.fcm_updated_at = new Date();
      await user.save();
      console.log("✅ FCM token auto-saved on login");
    }

    const token = jwt.sign({ id: user._id, username: user.username }, "secret123", { expiresIn: "24h" });

    res.json({
      status: true,
      message: "Login successful",
      user: { id: user._id, username: user.username },
      token
    });
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// --------------------------
// 🔹 Save FCM Token
// --------------------------
app.post("/backend/api/save-fcm-token", async (req, res) => {
  try {
    const { user_id, fcm_token, device_type } = req.body;

    if (!user_id || !fcm_token)
      return res.status(400).json({ status: false, message: "user_id and fcm_token are required" });

    const user = await User.findById(user_id);
    if (!user)
      return res.status(404).json({ status: false, message: "User not found" });

    user.fcm_token = fcm_token;
    user.device_type = device_type || "android";
    user.fcm_updated_at = new Date();
    await user.save();

    res.json({ status: true, message: "Token saved successfully" });
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// --------------------------
// 🔹 Get Leads by User ID (with pagination)
// --------------------------
app.post("/api/getLeadsByUserId", async (req, res) => {
  try {
    const { page = 1, limit = 10, user_id } = req.body;
    const skip = (page - 1) * limit;
    
    // Optional: Filter by user_id if provided
    const query = user_id ? { user_id } : {};
    
    const leads = await Lead.find(query)
      .sort({ createdAt: -1 }) // Latest first
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Lead.countDocuments(query);
    
    // Transform response to match frontend expectations
    const transformedLeads = leads.map(lead => ({
      id: lead._id,
      lead_name: lead.customer_name,
      phone: lead.customer_phone,
      requirement: lead.requirement,
      city: lead.city,
      status: lead.status,
      created_at: lead.createdAt
    }));
    
    res.json({
      status: true,
      message: "Leads fetched successfully",
      leads: transformedLeads,
      total: total,
      page: parseInt(page),
      totalPages: Math.ceil(total / limit)
    });
    
  } catch (err) {
    console.error("Error fetching leads:", err);
    res.status(500).json({ 
      status: false, 
      message: err.message 
    });
  }
});

// --------------------------
// 🔹 Add Lead (auto send notification)
// --------------------------
app.post("/api/addLeadsByUserId", async (req, res) => {
  try {
    let { user_id, customer_name, customer_phone, requirement, city, status } = req.body;

    // Validate required fields
    if (!customer_name) {
      return res.status(400).json({ 
        status: false, 
        message: "customer_name is required" 
      });
    }

    // If no user_id provided, find the most recent user with FCM token
    if (!user_id) {
      const user = await User.findOne({ fcm_token: { $ne: null } }).sort({ fcm_updated_at: -1 });
      if (user) user_id = user._id;
    }

    // Create new lead
    const lead = new Lead({
      user_id: user_id || null,
      customer_name,
      customer_phone,
      requirement,
      city,
      status: status || 'New Lead'
    });

    await lead.save();

    console.log("✅ Lead saved:", lead._id);

    // Send FCM notification
    if (user_id) {
      await sendFCMNotification(user_id, lead);
    }

    res.json({
      status: true,
      message: "Lead added successfully",
      data: {
        id: lead._id,
        customer_name: lead.customer_name,
        customer_phone: lead.customer_phone,
        requirement: lead.requirement,
        city: lead.city,
        status: lead.status,
        createdAt: lead.createdAt
      }
    });
  } catch (err) {
    console.error("❌ Error adding lead:", err);
    res.status(500).json({ status: false, message: err.message });
  }
});

// --------------------------
// 🔹 Get Today's Leads (Date filter)
// --------------------------
app.post("/api/getTodaysLeads", async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.body;
    
    // Get today's date range (IST timezone)
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    
    const endOfDay = new Date();
    endOfDay.setHours(23, 59, 59, 999);
    
    const skip = (page - 1) * limit;
    
    const leads = await Lead.find({
      createdAt: {
        $gte: startOfDay,
        $lte: endOfDay
      }
    })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Lead.countDocuments({
      createdAt: {
        $gte: startOfDay,
        $lte: endOfDay
      }
    });
    
    const transformedLeads = leads.map(lead => ({
      id: lead._id,
      lead_name: lead.customer_name,
      phone: lead.customer_phone,
      requirement: lead.requirement,
      city: lead.city,
      status: lead.status,
      created_at: lead.createdAt
    }));
    
    res.json({
      status: true,
      message: "Today's leads fetched successfully",
      leads: transformedLeads,
      total: total,
      page: parseInt(page),
      totalPages: Math.ceil(total / limit)
    });
    
  } catch (err) {
    console.error("Error fetching today's leads:", err);
    res.status(500).json({ 
      status: false, 
      message: err.message 
    });
  }
});

// --------------------------
// Start Server
// --------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
