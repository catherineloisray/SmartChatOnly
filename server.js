/* ================================================================
   SmartChatOnly — Backend Server v2
   Separate Admin Portal & Client Site
   E2E Encrypted Chat with Media Sharing
   ================================================================ */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', true); // Get real IP behind Render proxy
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 10e6 });

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const NOTIFICATIONS_FILE = path.join(DATA_DIR, 'notifications.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ========== JSON DB ==========
function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

let users = readJSON(USERS_FILE, {});
let messages = readJSON(MESSAGES_FILE, []);
let notifications = readJSON(NOTIFICATIONS_FILE, []);

function saveUsers() { writeJSON(USERS_FILE, users); }
function saveMessages() { writeJSON(MESSAGES_FILE, messages); }
function saveNotifications() { writeJSON(NOTIFICATIONS_FILE, notifications); }

function addNotification(type, message, data = {}) {
  const notif = { id: uuidv4(), type, message, data, timestamp: new Date().toISOString(), read: false };
  notifications.unshift(notif);
  if (notifications.length > 100) notifications = notifications.slice(0, 100);
  saveNotifications();
  // Push to admin if online
  const adminSocketId = onlineUsers.get('admin');
  if (adminSocketId) io.to(adminSocketId).emit('admin_notification', notif);
  return notif;
}

// ========== INIT ADMIN ==========
async function initAdmin() {
  if (!users['admin']) {
    const hash = await bcrypt.hash('AdminSecure!99', 10);
    users['admin'] = {
      username: 'admin', fullName: 'Admin', passwordHash: hash, role: 'admin',
      publicKey: null, encryptedPrivateKey: null, keySalt: null, keyIv: null,
      blocked: false, createdAt: new Date().toISOString()
    };
    saveUsers();
    console.log('Admin account created (admin / AdminSecure!99)');
  }
}

// ========== DEVICE & IP HELPERS ==========
function parseDevice(ua) {
  if (!ua) return 'Unknown Device';
  let device = '';
  if (/iPhone/.test(ua)) device = 'iPhone';
  else if (/iPad/.test(ua)) device = 'iPad';
  else if (/Android/.test(ua)) {
    const m = ua.match(/;\s*([^;)]+)\s*Build\//);
    device = m ? m[1].trim() : 'Android Device';
  }
  else if (/Windows/.test(ua)) device = 'Windows PC';
  else if (/Macintosh|Mac OS/.test(ua)) device = 'Mac';
  else if (/Linux/.test(ua)) device = 'Linux PC';
  else device = 'Unknown Device';
  let browser = '';
  if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/OPR\/|Opera/.test(ua)) browser = 'Opera';
  else if (/Chrome\//.test(ua) && !/Edg\//.test(ua)) browser = 'Chrome';
  else if (/Safari\//.test(ua) && !/Chrome\//.test(ua)) browser = 'Safari';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  return browser ? `${device} · ${browser}` : device;
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'Unknown';
}

// ========== MIDDLEWARE ==========
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const tokens = new Map();

function authMiddleware(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !tokens.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  req.username = tokens.get(token);
  req.user = users[req.username];
  if (!req.user) return res.status(401).json({ error: 'User not found' });
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ========== ROUTES: Serve separate pages ==========
// Client site at /
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'client.html'));
});

// Admin portal at /admin-portal
app.get('/admin-portal', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Static files (socket.io client, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// ========== AUTH ROUTES ==========
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, fullName, publicKey, encryptedPrivateKey, keySalt, keyIv, deviceInfo } = req.body;
    if (!username || !password || !fullName) return res.status(400).json({ error: 'All fields required' });
    if (username.length < 3) return res.status(400).json({ error: 'Username min 3 chars' });
    if (!/^[a-z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: lowercase, numbers, underscores only' });
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
    if (username === 'admin') return res.status(400).json({ error: 'Reserved username' });
    if (users[username]) return res.status(400).json({ error: 'Username already taken' });

    const hash = await bcrypt.hash(password, 10);
    users[username] = {
      username, fullName, passwordHash: hash, role: 'client',
      publicKey: publicKey || null, encryptedPrivateKey: encryptedPrivateKey || null,
      keySalt: keySalt || null, keyIv: keyIv || null,
      blocked: false, createdAt: new Date().toISOString()
    };
    saveUsers();

    const ip = getIP(req);
    const device = parseDevice(deviceInfo || req.headers['user-agent']);
    addNotification('signup', `New client signed up: ${fullName} (@${username})`, { username, fullName, ip, device });

    const token = uuidv4();
    tokens.set(token, username);
    res.json({ success: true, token, user: sanitizeUser(users[username]) });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password, portal, deviceInfo } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields required' });

    const user = users[username.toLowerCase()];
    if (!user) return res.status(400).json({ error: 'Account not found' });
    if (user.blocked) return res.status(403).json({ error: 'Your account has been suspended. Contact support.' });

    // Enforce portal separation
    if (portal === 'admin' && user.role !== 'admin') return res.status(403).json({ error: 'Admin access only' });
    if (portal === 'client' && user.role === 'admin') return res.status(403).json({ error: 'Please use the admin portal to sign in.' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(400).json({ error: 'Incorrect password' });

    const token = uuidv4();
    tokens.set(token, user.username);

    if (user.role === 'client') {
      const ip = getIP(req);
      const device = parseDevice(deviceInfo || req.headers['user-agent']);
      addNotification('login', `Client logged in: ${user.fullName} (@${user.username})`, { username: user.username, ip, device });
    }

    res.json({
      success: true, token,
      user: sanitizeUser(user),
      encryptedPrivateKey: user.encryptedPrivateKey,
      keySalt: user.keySalt,
      keyIv: user.keyIv
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/update-keys', authMiddleware, (req, res) => {
  const { publicKey, encryptedPrivateKey, keySalt, keyIv } = req.body;
  users[req.username].publicKey = publicKey;
  users[req.username].encryptedPrivateKey = encryptedPrivateKey;
  users[req.username].keySalt = keySalt;
  users[req.username].keyIv = keyIv;
  saveUsers();
  res.json({ success: true });
});

// ========== CONTACTS & MESSAGES ==========
app.get('/api/contacts', authMiddleware, (req, res) => {
  const list = [];
  if (req.user.role === 'admin') {
    for (const u of Object.values(users)) {
      if (u.role === 'client' && !u.blocked) list.push(sanitizeUser(u));
    }
  }
  // Clients get NO contact list — admin initiates
  res.json(list);
});

app.get('/api/messages', authMiddleware, (req, res) => {
  const withUser = req.query.with;
  if (!withUser) return res.status(400).json({ error: 'Missing "with" param' });
  const chatMsgs = messages.filter(m =>
    (m.from === req.username && m.to === withUser) ||
    (m.from === withUser && m.to === req.username)
  );
  res.json(chatMsgs);
});

// Client: get my conversations (only shows admin if admin has messaged them)
app.get('/api/my-conversations', authMiddleware, (req, res) => {
  if (req.user.role === 'admin') return res.json([]);
  // Find if admin has sent any messages to this client
  const hasMessages = messages.some(m =>
    (m.from === 'admin' && m.to === req.username) ||
    (m.from === req.username && m.to === 'admin')
  );
  if (hasMessages && users['admin']) {
    res.json([sanitizeUser(users['admin'])]);
  } else {
    res.json([]);
  }
});

app.get('/api/publickey/:username', authMiddleware, (req, res) => {
  const user = users[req.params.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ publicKey: user.publicKey });
});

// ========== ADMIN: User Management ==========
app.get('/api/admin/users', authMiddleware, adminOnly, (req, res) => {
  const list = Object.values(users).filter(u => u.role === 'client').map(u => ({
    ...sanitizeUser(u), blocked: u.blocked || false
  }));
  res.json(list);
});

app.post('/api/admin/block/:username', authMiddleware, adminOnly, (req, res) => {
  const user = users[req.params.username];
  if (!user || user.role === 'admin') return res.status(404).json({ error: 'User not found' });
  user.blocked = true;
  saveUsers();
  // Disconnect blocked user
  const sid = onlineUsers.get(req.params.username);
  if (sid) io.to(sid).emit('account_blocked');
  res.json({ success: true });
});

app.post('/api/admin/unblock/:username', authMiddleware, adminOnly, (req, res) => {
  const user = users[req.params.username];
  if (!user || user.role === 'admin') return res.status(404).json({ error: 'User not found' });
  user.blocked = false;
  saveUsers();
  res.json({ success: true });
});

app.delete('/api/admin/delete/:username', authMiddleware, adminOnly, (req, res) => {
  const username = req.params.username;
  if (!users[username] || users[username].role === 'admin') return res.status(404).json({ error: 'User not found' });
  delete users[username];
  saveUsers();
  messages = messages.filter(m => m.from !== username && m.to !== username);
  saveMessages();
  const sid = onlineUsers.get(username);
  if (sid) io.to(sid).emit('account_deleted');
  res.json({ success: true });
});

app.get('/api/admin/notifications', authMiddleware, adminOnly, (req, res) => {
  res.json(notifications);
});

app.post('/api/admin/notifications/read', authMiddleware, adminOnly, (req, res) => {
  notifications.forEach(n => n.read = true);
  saveNotifications();
  res.json({ success: true });
});

// Track client site visits
app.post('/api/track-visit', (req, res) => {
  const ip = getIP(req);
  const device = parseDevice(req.body.deviceInfo || req.headers['user-agent']);
  addNotification('visit', `Site visitor — ${device}`, { ip, device, timestamp: new Date().toISOString() });
  res.json({ ok: true });
});

// ========== SOCKET.IO ==========
const onlineUsers = new Map();

io.on('connection', (socket) => {
  let socketUser = null;

  socket.on('authenticate', (token) => {
    const username = tokens.get(token);
    if (!username) return socket.emit('auth_error', 'Invalid token');
    const user = users[username];
    if (!user) return socket.emit('auth_error', 'User not found');
    if (user.blocked) return socket.emit('account_blocked');

    socketUser = username;
    onlineUsers.set(username, socket.id);
    io.emit('user_online', { username, online: true });
    socket.emit('online_users', Array.from(onlineUsers.keys()));
  });

  socket.on('send_message', (msg) => {
    if (!socketUser) return;
    const sender = users[socketUser];
    if (!sender || sender.blocked) return;

    const message = {
      id: uuidv4(), from: socketUser, to: msg.to,
      type: msg.type || 'text',
      encrypted: msg.encrypted,
      encKeyForSender: msg.encKeyForSender,
      encKeyForRecipient: msg.encKeyForRecipient,
      mediaType: msg.mediaType || null,
      mediaName: msg.mediaName || null,
      timestamp: new Date().toISOString()
    };
    messages.push(message);
    saveMessages();

    const recipientSocket = onlineUsers.get(msg.to);
    if (recipientSocket) io.to(recipientSocket).emit('new_message', message);
    socket.emit('message_sent', message);
  });

  socket.on('typing', (data) => {
    if (!socketUser) return;
    const s = onlineUsers.get(data.to);
    if (s) io.to(s).emit('user_typing', { from: socketUser });
  });

  socket.on('stop_typing', (data) => {
    if (!socketUser) return;
    const s = onlineUsers.get(data.to);
    if (s) io.to(s).emit('user_stop_typing', { from: socketUser });
  });

  socket.on('disconnect', () => {
    if (socketUser) {
      onlineUsers.delete(socketUser);
      io.emit('user_online', { username: socketUser, online: false });
    }
  });
});

function sanitizeUser(u) {
  return { username: u.username, fullName: u.fullName, role: u.role, publicKey: u.publicKey, createdAt: u.createdAt };
}

// ========== AUTO-DELETE MESSAGES EVERY 2 HOURS ==========
const AUTO_DELETE_INTERVAL = 2 * 60 * 60 * 1000; // 2 hours

setInterval(() => {
  if (messages.length === 0) return;
  messages = [];
  saveMessages();
  io.emit('messages_cleared');
  console.log(`[Auto-Delete] All messages cleared at ${new Date().toISOString()}`);
}, AUTO_DELETE_INTERVAL);

// ========== START ==========
initAdmin().then(() => {
  server.listen(PORT, () => {
    console.log(`SmartChatOnly v2 running on port ${PORT}`);
    console.log(`Client site: /`);
    console.log(`Admin portal: /admin-portal`);
    console.log(`Admin login: admin / AdminSecure!99`);
    console.log(`Messages auto-delete every 2 hours`);
  });
});
