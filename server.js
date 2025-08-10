require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const fs = require('fs');
const cron = require('node-cron');
const cloudinary = require('cloudinary').v2;
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Serve all static files except see.html
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('see.html')) {
      // Allow if admin is logged in (session.admin exists)
      if (res.req && res.req.session && res.req.session.admin) {
        return;
      }
      res.statusCode = 403;
      res.setHeader('Content-Type', 'text/html');
      res.end(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Access Forbidden</title>
          <style>
            body {
              background: linear-gradient(135deg, #ff5858 0%, #f09819 100%);
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              margin: 0;
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .forbidden-container {
              background: #fff;
              border-radius: 18px;
              box-shadow: 0 8px 32px rgba(0,0,0,0.18);
              padding: 48px 36px;
              text-align: center;
              max-width: 420px;
            }
            .forbidden-icon {
              font-size: 80px;
              color: #e74c3c;
              margin-bottom: 18px;
              animation: shake 0.7s infinite alternate;
            }
            @keyframes shake {
              0% { transform: rotate(-7deg); }
              100% { transform: rotate(7deg); }
            }
            .forbidden-title {
              color: #e74c3c;
              font-size: 2.2rem;
              font-weight: bold;
              margin-bottom: 12px;
              letter-spacing: 1px;
            }
            .forbidden-message {
              color: #2c3e50;
              font-size: 1.1rem;
              margin-bottom: 24px;
            }
            .home-btn {
              background: linear-gradient(90deg, #f09819 0%, #ff5858 100%);
              color: #fff;
              border: none;
              border-radius: 8px;
              padding: 12px 32px;
              font-size: 1rem;
              font-weight: 600;
              cursor: pointer;
              box-shadow: 0 2px 8px rgba(0,0,0,0.08);
              transition: background 0.2s, transform 0.2s;
            }
            .home-btn:hover {
              background: linear-gradient(90deg, #ff5858 0%, #f09819 100%);
              transform: scale(1.05);
            }
          </style>
        </head>
        <body>
          <div class="forbidden-container">
            <div class="forbidden-icon">&#9888;</div>
            <div class="forbidden-title">Access Forbidden</div>
            <div class="forbidden-message">
              <strong>Warning:</strong> You are not allowed to access this page directly.<br>
              Only the owner can view this page from the Owner Page.
            </div>
            <button class="home-btn" onclick="window.location.replace('/')">Return Home</button>
          </div>
        </body>
        </html>
      `);
      return false;
    }
  }
}));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("mongo connected"))
  .catch((err) => console.log("mongo error", err));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const Admin = mongoose.model('Admin', new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  contact: String
}));

const Customer = mongoose.model('Customer', new mongoose.Schema({
  name: String,
  email: String,
  contact: String,
  password: String,
  notes: { type: String, default: '' }, // For admin notes about customer
  createdAt: { type: Date, default: Date.now } // Track registration date
}));

const Product = mongoose.model('Product', new mongoose.Schema({
  name: String,
  amount: Number,
  description: String,
  url: String,
  createdAt: { type: Date, default: Date.now }
}));

const Order = mongoose.model('Order', new mongoose.Schema({
  name: String,
  product: String,
  amount: Number,
  quantity: Number,
  email: String,
  contact: String,
  status: { type: String, default: 'Pending' }, // For approval workflow
  orderStatus: { type: String, default: 'pending' }, // For success/failure tracking  
  notes: { type: String, default: '' }, // For admin notes
  createdAt: { type: Date, default: Date.now }
}));

const BusinessNote = mongoose.model('BusinessNote', new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  date: { type: Date, default: Date.now },
  adminEmail: String, // Track which admin created the note
  attachments: [{
    filename: String,
    originalName: String,
    size: Number,
    mimetype: String,
    url: String, // Cloudinary URL
    publicId: String // Cloudinary public ID for deletion
  }],
  location: {
    latitude: { type: Number, required: false },
    longitude: { type: Number, required: false },
    address: { type: String, required: false },
    timestamp: { type: Date, required: false },
    accuracy: { type: Number, required: false },
  googleMapsUrl: { type: String, required: false }, // Google Maps URL for direct linking
    capturedAt: { type: Date, required: false }
  },
  createdAt: { type: Date, default: Date.now }
}));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function sendEmail(to, subject, html) {
  // Wrap all emails in a professional XIN Investment template
  const wrappedHtml = `
    <div style="background:linear-gradient(135deg,#f8ffae 0%,#43c6ac 100%);min-height:100vh;padding:40px 0;">
      <div style="max-width:520px;margin:40px auto;background:#fff;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,0.10);padding:36px 28px;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">
        <div style="text-align:center;margin-bottom:18px;">
          <span style="font-size:2.2rem;color:#43c6ac;font-weight:bold;letter-spacing:1px;">XIN Investment</span>
        </div>
        <div style="color:#2c3e50;font-size:1.08rem;line-height:1.7;">
          ${html}
        </div>
        <div style="margin-top:32px;text-align:center;color:#888;font-size:0.98rem;">
          <div>Thank you for choosing XIN Investment.</div>
          <div style="margin-top:10px;">
            <b>Contact Us:</b><br>
            <span>📧 Email: <a href=\"mailto:lwingageazi@gmail.com\" style=\"color:#43c6ac;\">lwingageazi@gmail.com</a></span><br>
            <span>📞 Phone: <a href=\"tel:+255741131500\" style=\"color:#43c6ac;\">+255 741 131 500</a> (WhatsApp Available)</span><br>
            <span>📍 Office Location: Isesa Primary School, Sumbawanga, Tanzania</span><br>
            <span>🌐 Website: <a href=\"https://www.elixins.com\" style=\"color:#43c6ac;\">www.elixins.com</a></span>
          </div>
        </div>
      </div>
    </div>
  `;
  transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: `XIN Investment - ${subject}`,
    html: wrappedHtml
  }, err => {
    if (err) console.log('Email error:', err.message);
  });
}

// === ADMIN REGISTER ===
app.post('/adminregister', async (req, res) => {
  try {
    const { name, email, password, contact } = req.body;
    const exists = await Admin.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Admin already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ name, email, password: hashedPassword, contact });
    await newAdmin.save();

    req.session.admin = { name: newAdmin.name, email: newAdmin.email };
    return res.redirect('/admindashboard.html');
  } catch (err) {
    console.error('Admin registration failed:', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// === ADMIN LOGIN ===
app.post('/adminlogin', async (req, res) => {
  const { email, password } = req.body;
  const admin = await Admin.findOne({ email });
  if (!admin) return res.send('Invalid credentials');

  const isMatch = await bcrypt.compare(password, admin.password);
  if (!isMatch) return res.send('Invalid credentials');

  req.session.admin = { email: admin.email, name: admin.name, contact: admin.contact };
  res.redirect('/admindashboard.html');
});

app.get('/getadmin', (req, res) => {
  if (!req.session.admin) return res.status(401).json({ error: 'Unauthorized' });
  res.json(req.session.admin);
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/adminlogin.html'));
});

// Create secure session token for see.html access
app.post('/create-user-view-session', (req, res) => {
  // Check if admin is logged in
  if (!req.session.admin) {
    return res.status(401).json({ success: false, message: 'Admin authentication required' });
  }
  
  // Generate secure token
  const token = Math.random().toString(36).substring(2) + Date.now().toString(36);
  
  // Store token in session with expiration (5 minutes)
  req.session.viewUsersToken = {
    token: token,
    expires: Date.now() + (5 * 60 * 1000) // 5 minutes from now
  };
  
  res.json({ success: true, token: token });
});

app.get('/admindashboard.html', (req, res, next) => {
  if (!req.session.admin) return res.redirect('/adminlogin.html');
  next();
}, express.static(path.join(__dirname, 'public', 'admindashboard.html')));

// Protect see.html with token validation - NO DIRECT ACCESS ALLOWED
app.get('/see.html', (req, res, next) => {
  const token = req.query.token;
  if (!token || !req.session.viewUsersToken || req.session.viewUsersToken.token !== token || req.session.viewUsersToken.expires < Date.now()) {
    return res.redirect('/error.html');
  } else {
    return next();
  }
}, express.static(path.join(__dirname, 'public', 'see.html')));

// === CUSTOMER REGISTER ===
app.post('/register', async (req, res) => {
  const { name, email, contact, password } = req.body;
  const exist = await Customer.findOne({ email });
  if (exist) return res.json({ success: false, message: 'Customer already exists' });
  await Customer.create({ name, email, contact, password });
  sendEmail(email, 'Welcome to XIN Investment', `
    <h2 style="color:#43c6ac;">Welcome, ${name}!</h2>
    <p>Thank you for registering with <b>XIN Investment</b>. We are excited to have you as part of our community. Explore our products and services designed to help you grow and succeed in agriculture.</p>
  `);
  res.json({ success: true });
});

// === CUSTOMER LOGIN ===
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await Customer.findOne({ email, password });
  if (!user) return res.json({ success: false, message: 'Invalid credentials' });
  res.json({ success: true, user: { name: user.name, email: user.email, contact: user.contact } });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

app.post('/uploadproduct', upload.single('media'), async (req, res) => {
  try {
    const { name, amount, description } = req.body;
    const result = await cloudinary.uploader.upload(req.file.path, { resource_type: "auto" });
    await Product.create({ name, amount, description, url: result.secure_url });

    const customers = await Customer.find();
    customers.forEach(c => {
      sendEmail(c.email, 'New Product Announcement', `
        <h2 style="color:#43c6ac;">New Product: ${name}</h2>
        <p>Dear valued customer,</p>
        <p>We are pleased to announce a new product now available at XIN Investment:</p>
        <ul>
          <li><b>Product:</b> ${name}</li>
          <li><b>Price:</b> ${amount} TZS</li>
        </ul>
        <img src="${result.secure_url}" style="width:200px;border-radius:8px;margin:16px 0;"/>
        <p><a href="http://your-website.com" style="color:#43c6ac;font-weight:bold;">Visit our website to learn more & order now!</a></p>
      `);
    });
    fs.unlinkSync(req.file.path);
    res.redirect('/admindashboard.html');
  } catch (err) {
    console.error(err);
    res.status(500).send('Upload failed');
  }
});

app.get('/products', async (req, res) => {
  try {
    const data = await Product.find();
    res.json(data);
  } catch (err) {
    res.status(500).send('Failed to load products');
  }
});

// Get product price by name for real-time calculation
app.get('/product/:name', async (req, res) => {
  try {
    const product = await Product.findOne({ name: req.params.name });
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ name: product.name, amount: product.amount });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get product' });
  }
});

app.get('/orders', async (req, res) => {
  try {
    const data = await Order.find();
    res.json(data);
  } catch (err) {
    res.status(500).send('Failed to load orders');
  }
});

app.post('/placeorder', async (req, res) => {
  try {
    const { product, amount, email, contact, quantity } = req.body;
    const customer = await Customer.findOne({ email });
    const name = customer ? customer.name : '';
    await Order.create({ name, product, amount, quantity, email, contact });
    sendEmail(email, 'Order Confirmation', `
      <h2 style="color:#43c6ac;">Order Received</h2>
      <p>Dear customer,</p>
      <p>Your order for <b>${quantity}</b> x <b>${product}</b> (total: <b>${amount} TZS</b>) has been received by XIN Investment. We will process your order and notify you when it is approved or shipped.</p>
    `);
    res.json({ success: true, message: 'Order placed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Order failed' });
  }
});

// --- NEW: Get orders of a specific user ---
app.get('/myorders', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).json({ message: 'Email required' });

    const orders = await Order.find({ email });
    res.json(orders);
  } catch (err) {
    console.error('Failed to fetch user orders:', err);
    res.status(500).json({ message: 'Failed to fetch orders' });
  }
});

// --- NEW: Delete a user order ---
app.delete('/orders/:id', async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Order deleted successfully' });
  } catch (err) {
    console.error('Failed to delete order:', err);
    res.status(500).json({ message: 'Failed to delete order' });
  }
});

// --- NEW: Update a user order ---
app.put('/orders/:id', async (req, res) => {
  try {
    const { quantity, amount } = req.body;
    if (!quantity || !amount) return res.status(400).json({ message: 'Quantity and amount required' });

    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ message: 'Order not found' });

    order.quantity = quantity;
    order.amount = amount;
    await order.save();

    res.json({ success: true, message: 'Order updated successfully' });
  } catch (err) {
    console.error('Failed to update order:', err);
    res.status(500).json({ message: 'Failed to update order' });
  }
});

// Update order status (successful/failed)
app.put('/api/orders/:id/status', async (req, res) => {
  try {
    const { orderStatus } = req.body;
    const validStatuses = ['pending', 'successful', 'failed'];
    
    if (!validStatuses.includes(orderStatus)) {
      return res.status(400).json({ error: 'Invalid order status' });
    }

    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    order.orderStatus = orderStatus;
    await order.save();

    res.json({ success: true, message: `Order status updated to ${orderStatus}` });
  } catch (err) {
    console.error('Failed to update order status:', err);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// Update order notes
app.put('/api/orders/:id/notes', async (req, res) => {
  try {
    const { notes } = req.body;
    
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    order.notes = notes || '';
    await order.save();

    res.json({ success: true, message: 'Order notes updated successfully' });
  } catch (err) {
    console.error('Failed to update order notes:', err);
    res.status(500).json({ error: 'Failed to update order notes' });
  }
});

// Update customer notes
app.put('/api/customers/:id/notes', async (req, res) => {
  try {
    const { notes } = req.body;
    
    const customer = await Customer.findById(req.params.id);
    if (!customer) return res.status(404).json({ error: 'Customer not found' });

    customer.notes = notes || '';
    await customer.save();

    res.json({ success: true, message: 'Customer notes updated successfully' });
  } catch (err) {
    console.error('Failed to update customer notes:', err);
    res.status(500).json({ error: 'Failed to update customer notes' });
  }
});

// Update customer information
app.post('/api/customers/update', async (req, res) => {
  try {
    const { id, name, email, contact } = req.body;
    
    if (!id || !name || !email || !contact) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if email is already taken by another customer
    const existingCustomer = await Customer.findOne({ email, _id: { $ne: id } });
    if (existingCustomer) {
      return res.status(400).json({ error: 'Email already exists for another customer' });
    }

    const customer = await Customer.findByIdAndUpdate(
      id, 
      { name, email, contact }, 
      { new: true }
    );
    
    if (!customer) return res.status(404).json({ error: 'Customer not found' });

    res.json({ success: true, message: 'Customer updated successfully', customer });
  } catch (err) {
    console.error('Failed to update customer:', err);
    res.status(500).json({ error: 'Failed to update customer' });
  }
});

// Statistics API endpoint
app.get('/api/statistics', async (req, res) => {
  try {
    const period = req.query.period || '7days';
    
    // Calculate date range based on period
    let startDate;
    const now = new Date();
    
    switch (period) {
      case '24hours':
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case '7days':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30days':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      case '90days':
        startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    }

    // Get orders within the period
    const orders = await Order.find({
      createdAt: { $gte: startDate }
    });

    // Get customers within the period (for user registrations as visitors proxy)
    const customers = await Customer.find({
      createdAt: { $gte: startDate }
    });

    // Get all customers for login simulation
    const allCustomers = await Customer.find();

    // Calculate statistics
    const totalOrders = orders.length;
    const totalRevenue = orders.reduce((sum, order) => sum + (order.amount * order.quantity || 0), 0);
    const newCustomers = customers.length; // New registrations in period
    const totalCustomers = allCustomers.length;

    // Group orders by product for rankings
    const productStats = {};
    orders.forEach(order => {
      if (!productStats[order.product]) {
        productStats[order.product] = { name: order.product, count: 0, revenue: 0 };
      }
      productStats[order.product].count += order.quantity || 1;
      productStats[order.product].revenue += order.amount * order.quantity || order.amount || 0;
    });

    // Get ALL-TIME product rankings based on SUCCESSFUL and FAILED orders (completed orders)
    const completedOrders = await Order.find({
      $or: [
        { orderStatus: 'successful' },
        { orderStatus: 'failed' }
      ]
    });

    const allTimeProductStats = {};
    completedOrders.forEach(order => {
      if (!allTimeProductStats[order.product]) {
        allTimeProductStats[order.product] = { 
          name: order.product, 
          totalQuantity: 0, 
          totalRevenue: 0,
          orderCount: 0,
          successfulOrders: 0,
          failedOrders: 0,
          successfulQuantity: 0,
          failedQuantity: 0,
          successfulRevenue: 0,
          failedRevenue: 0
        };
      }
      
      const quantity = order.quantity || 1;
      const revenue = (order.amount * quantity) || order.amount || 0;
      
      // Add to totals
      allTimeProductStats[order.product].totalQuantity += quantity;
      allTimeProductStats[order.product].totalRevenue += revenue;
      allTimeProductStats[order.product].orderCount += 1;
      
      // Track by status
      if (order.orderStatus === 'successful') {
        allTimeProductStats[order.product].successfulOrders += 1;
        allTimeProductStats[order.product].successfulQuantity += quantity;
        allTimeProductStats[order.product].successfulRevenue += revenue;
      } else if (order.orderStatus === 'failed') {
        allTimeProductStats[order.product].failedOrders += 1;
        allTimeProductStats[order.product].failedQuantity += quantity;
        allTimeProductStats[order.product].failedRevenue += revenue;
      }
    });

    const productRankings = Object.values(allTimeProductStats)
      .sort((a, b) => b.totalQuantity - a.totalQuantity) // Sort by total quantity
      .slice(0, 10) // Top 10 products
      .map(product => ({
        name: product.name,
        totalQuantity: product.totalQuantity,
        totalRevenue: product.totalRevenue,
        totalOrders: product.orderCount,
        successfulOrders: product.successfulOrders,
        failedOrders: product.failedOrders,
        successfulQuantity: product.successfulQuantity,
        failedQuantity: product.failedQuantity,
        successfulRevenue: product.successfulRevenue,
        failedRevenue: product.failedRevenue,
        successRate: product.orderCount > 0 ? Math.round((product.successfulOrders / product.orderCount) * 100) : 0,
        avgOrderValue: product.orderCount > 0 ? Math.round(product.totalRevenue / product.orderCount) : 0
      }));

    // Create realistic statistics based on actual data
    const statisticsData = {
      visits: [{ count: newCustomers + (totalOrders * 2) }], // New customers + order views
      logins: [{ count: Math.floor(totalCustomers * 0.6) + newCustomers }], // 60% existing + new customers
      orders: [{ count: totalOrders, totalAmount: totalRevenue }],
      productRankings: productRankings
    };

    res.json(statisticsData);
  } catch (error) {
    console.error('Statistics error:', error);
    res.status(500).json({ error: 'Failed to load statistics' });
  }
});

// === BUSINESS NOTES API ROUTES ===
// Get all business notes
app.get('/api/business-notes', async (req, res) => {
  try {
    const notes = await BusinessNote.find().sort({ createdAt: -1 });
    res.json({ success: true, notes });
  } catch (error) {
    console.error('Failed to fetch notes:', error);
    res.status(500).json({ success: false, message: 'Failed to load business notes' });
  }
});

// Create new business note with file attachments
app.post('/api/business-notes', upload.array('attachments', 10), async (req, res) => {
  try {
    const { title, content, date, location } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ success: false, message: 'Title and content are required' });
    }

    const attachments = [];
    
    // Upload files to Cloudinary if any
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        try {
          const result = await cloudinary.uploader.upload(file.path, {
            folder: 'business-notes',
            resource_type: 'auto', // Handles images, videos, and raw files
            public_id: `note-${Date.now()}-${Math.random().toString(36).substring(2)}`
          });
          
          attachments.push({
            filename: file.filename,
            originalName: file.originalname,
            size: file.size,
            mimetype: file.mimetype,
            url: result.secure_url,
            publicId: result.public_id
          });
          
          // Clean up local file
          require('fs').unlinkSync(file.path);
        } catch (uploadError) {
          console.error('Cloudinary upload error:', uploadError);
          // Continue processing other files even if one fails
        }
      }
    }

    // Parse location data if provided
    let locationData = null;
    if (location) {
      try {
        locationData = JSON.parse(location);
      } catch (parseError) {
        console.error('Location parsing error:', parseError);
      }
    }

    const note = new BusinessNote({
      title,
      content,
      date: date || new Date(),
      adminEmail: req.session.admin ? req.session.admin.email : 'unknown',
      attachments: attachments,
      location: locationData,
      createdAt: new Date()
    });

    await note.save();
    
    // Enhanced success message with location and attachment details
    let message = 'Business note saved successfully';
    if (locationData) {
      message += ` with location (${locationData.address || locationData.latitude.toFixed(4) + ', ' + locationData.longitude.toFixed(4)})`;
    }
    if (attachments.length > 0) {
      message += ` and ${attachments.length} attachment(s)`;
    }
    
    res.json({ 
      success: true, 
      message: message,
      note: note,
      hasLocation: !!locationData,
      locationDetails: locationData ? {
        address: locationData.address,
        coordinates: `${locationData.latitude}, ${locationData.longitude}`,
        googleMapsUrl: `https://www.google.com/maps?q=${locationData.latitude},${locationData.longitude}&z=16`
      } : null
    });
  } catch (error) {
    console.error('Failed to save note:', error);
    res.status(500).json({ success: false, message: 'Failed to save business note' });
  }
});

// Update business note with new attachments
app.put('/api/business-notes/:id', upload.array('attachments', 10), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, date } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ success: false, message: 'Title and content are required' });
    }

    const existingNote = await BusinessNote.findById(id);
    if (!existingNote) {
      return res.status(404).json({ success: false, message: 'Note not found' });
    }

    const newAttachments = [];
    
    // Upload new files to Cloudinary if any
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        try {
          const result = await cloudinary.uploader.upload(file.path, {
            folder: 'business-notes',
            resource_type: 'auto',
            public_id: `note-${Date.now()}-${Math.random().toString(36).substring(2)}`
          });
          
          newAttachments.push({
            filename: file.filename,
            originalName: file.originalname,
            size: file.size,
            mimetype: file.mimetype,
            url: result.secure_url,
            publicId: result.public_id
          });
          
          // Clean up local file
          require('fs').unlinkSync(file.path);
        } catch (uploadError) {
          console.error('Cloudinary upload error:', uploadError);
        }
      }
    }

    // Combine existing attachments with new ones
    const updatedAttachments = [...existingNote.attachments, ...newAttachments];

    // Update the note
    const updatedNote = await BusinessNote.findByIdAndUpdate(
      id,
      {
        title,
        content,
        date: date || existingNote.date,
        attachments: updatedAttachments,
        adminEmail: req.session.admin ? req.session.admin.email : existingNote.adminEmail
      },
      { new: true }
    );

    res.json({ 
      success: true, 
      message: `Business note updated successfully${newAttachments.length > 0 ? ` with ${newAttachments.length} new attachment(s)` : ''}`, 
      note: updatedNote 
    });
  } catch (error) {
    console.error('Failed to update note:', error);
    res.status(500).json({ success: false, message: 'Failed to update business note' });
  }
});

// Add location to existing business note
app.put('/api/business-notes/:id/location', async (req, res) => {
  try {
    const { id } = req.params;
    const { location } = req.body;

    if (!location || !location.latitude || !location.longitude) {
      return res.status(400).json({ success: false, message: 'Valid location data is required' });
    }

    const updatedNote = await BusinessNote.findByIdAndUpdate(
      id,
      { location: location },
      { new: true }
    );

    if (!updatedNote) {
      return res.status(404).json({ success: false, message: 'Business note not found' });
    }

    res.json({ 
      success: true, 
      message: `Location added to note successfully`, 
      note: updatedNote 
    });
  } catch (error) {
    console.error('Failed to add location to note:', error);
    res.status(500).json({ success: false, message: 'Failed to add location to note' });
  }
});

// Delete business note and its attachments
app.delete('/api/business-notes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const note = await BusinessNote.findById(id);
    
    if (!note) {
      return res.status(404).json({ success: false, message: 'Note not found' });
    }

    // Delete attachments from Cloudinary
    if (note.attachments && note.attachments.length > 0) {
      for (const attachment of note.attachments) {
        try {
          if (attachment.publicId) {
            await cloudinary.uploader.destroy(attachment.publicId, { resource_type: 'auto' });
          }
        } catch (deleteError) {
          console.error('Failed to delete attachment from Cloudinary:', deleteError);
          // Continue with note deletion even if file deletion fails
        }
      }
    }

    // Delete the note from database
    await BusinessNote.findByIdAndDelete(id);

    res.json({ success: true, message: 'Business note and attachments deleted successfully' });
  } catch (error) {
    console.error('Failed to delete note:', error);
    res.status(500).json({ success: false, message: 'Failed to delete business note' });
  }
});

app.post('/updateadmin', async (req, res) => {
  const { name, email, contact } = req.body;
  try {
    const admin = await Admin.findOneAndUpdate({ email }, { name, contact }, { new: true });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    req.session.admin = { email: admin.email, name: admin.name, contact: admin.contact };
    res.json(admin);
  } catch {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.post('/updateproduct', async (req, res) => {
  const { id, name, amount, description } = req.body;
  try {
    const product = await Product.findByIdAndUpdate(id, { name, amount, description }, { new: true });
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Update failed' });
  }
});

// Update product photo
app.post('/updateproductphoto/:id', upload.single('media'), async (req, res) => {
  try {
    const productId = req.params.id;
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    // Upload new image to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, { resource_type: "auto" });

    // Delete old image from Cloudinary if it exists
    if (product.url) {
      const urlParts = product.url.split('/');
      const fileName = urlParts[urlParts.length - 1];
      const publicId = fileName.substring(0, fileName.lastIndexOf('.'));
      
      const ext = fileName.split('.').pop().toLowerCase();
      const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff'];
      const videoExts = ['mp4', 'webm', 'ogg', 'avi', 'mov', 'flv', 'mkv'];

      let resourceType = 'image';
      if (videoExts.includes(ext)) {
        resourceType = 'video';
      } else if (!imageExts.includes(ext)) {
        resourceType = 'raw';
      }

      await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
    }

    // Update product with new image URL
    await Product.findByIdAndUpdate(productId, { url: result.secure_url });

    // Clean up local file
    fs.unlinkSync(req.file.path);

    res.json({ success: true, message: 'Product photo updated successfully' });
  } catch (err) {
    console.error('Update product photo error:', err);
    res.status(500).json({ error: 'Photo update failed' });
  }
});

app.delete('/deleteproduct/:id', async (req, res) => {
  try {
    const prod = await Product.findById(req.params.id);
    if (!prod) return res.status(404).json({ error: 'Product not found' });

    if (prod.url) {
      const urlParts = prod.url.split('/');
      const fileName = urlParts[urlParts.length - 1];
      const publicId = fileName.substring(0, fileName.lastIndexOf('.'));

      const ext = fileName.split('.').pop().toLowerCase();
      const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff'];
      const videoExts = ['mp4', 'webm', 'ogg', 'avi', 'mov', 'flv', 'mkv'];

      let resourceType = 'image';
      if (videoExts.includes(ext)) {
        resourceType = 'video';
      } else if (!imageExts.includes(ext)) {
        resourceType = 'raw';
      }

      await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
    }

    await Order.deleteMany({ product: prod.name });
    await Product.findByIdAndDelete(req.params.id);

    res.json({ success: true, message: 'Product and related orders deleted.' });
  } catch (err) {
    console.error('Delete product error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.post('/approveorder/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (order) {
      order.status = 'Approved';
      await order.save();
      sendEmail(order.email, 'Order Approved', `
        <h2 style="color:#43c6ac;">Order Approved</h2>
        <p>Dear customer,</p>
        <p>Your order for <b>${order.product}</b> has been <b>approved</b> by XIN Investment. Thank you for your trust in us!</p>
      `);
    }
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Approval failed' });
  }
});

app.delete('/deleteorder/:id', async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Delete failed' });
  }
});

cron.schedule('0 8,18 * * *', async () => {
  try {
    const users = await Customer.find();
    users.forEach(u => {
      sendEmail(u.email, 'Daily Offers & News', `
        <h2 style="color:#43c6ac;">Hello ${u.name},</h2>
        <p>Check out the latest offers and updates from XIN Investment! Visit our shop for new products and exclusive deals.</p>
        <p><a href="http://your-website.com" style="color:#43c6ac;font-weight:bold;">Visit Our Shop</a></p>
      `);
    });
    console.log('Daily marketing emails sent');
  } catch (err) {
    console.error('Error sending marketing emails:', err);
  }
});

app.post('/admin-forgot-password', async (req, res) => {
  const { email } = req.body;
  const admin = await Admin.findOne({ email });
  if (!admin) return res.json({ success: false, message: 'Email not found.' });

  const newPassword = Math.random().toString(36).slice(-8);
  const hashed = await bcrypt.hash(newPassword, 10);
  admin.password = hashed;
  await admin.save();

  sendEmail(email, 'Admin Password Reset', `
    <h2 style="color:#43c6ac;">Password Reset</h2>
    <p>Dear Admin,</p>
    <p>Your new admin password for XIN Investment is: <b>${newPassword}</b></p>
    <p>For security, please log in and change your password as soon as possible.</p>
  `);
  res.json({ success: true, message: 'A new password has been sent to your email.' });
});

app.get('/api/users', async (req, res) => {
  try {
    const admins = await Admin.find();
    const customers = await Customer.find();
    res.json({ admins, customers });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});
app.delete('/api/admins/:id', async (req, res) => {
  try {
    await Admin.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete admin' });
  }
});

app.delete('/api/customers/:id', async (req, res) => {
  try {
    await Customer.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete customer' });
  }
});
// Update order quantity and amount
app.put('/updateorder', async (req, res) => {
  try {
    const { orderId, quantity } = req.body;
    if (!orderId || !quantity || quantity < 1) {
      return res.status(400).json({ message: 'Invalid orderId or quantity' });
    }

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: 'Order not found' });

    order.quantity = quantity;
    order.amount = order.product ? order.amount / order.quantity * quantity : order.amount; // fallback
    // More precise recalculation:
    // Find product price and calculate amount accordingly:
    const product = await Product.findOne({ name: order.product });
    if (product) {
      order.amount = product.amount * quantity;
    }

    await order.save();
    res.json({ success: true, message: 'Order updated successfully' });
  } catch (err) {
    console.error('Failed to update order:', err);
    res.status(500).json({ message: 'Failed to update order' });
  }
});

// Delete order by id
app.delete('/deleteorder', async (req, res) => {
  try {
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ message: 'orderId is required' });

    const deleted = await Order.findByIdAndDelete(orderId);
    if (!deleted) return res.status(404).json({ message: 'Order not found' });

    res.json({ success: true, message: 'Order deleted successfully' });
  } catch (err) {
    console.error('Failed to delete order:', err);
    res.status(500).json({ message: 'Failed to delete order' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
