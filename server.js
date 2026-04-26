/* ================================================================
   SmartChatOnly — Backend Server
   Express + Socket.io + JSON file storage
   End-to-End Encryption: server NEVER sees plaintext messages
   ================================================================ */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 10e6 });

// ========== CONFIG ==========
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const MEDIA_DIR = path.join(DATA_DIR, 'media');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

// Ensure data directories exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(MEDIA_DIR)) fs.mkdirSync(MEDIA_DIR, { recursive: true });

// ========== SIMPLE JSON DB ==========
function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

let users = readJSON(USERS_FILE, {});
let messages = readJSON(MESSAGES_FILE, []);

function saveUsers() { writeJSON(USERS_FILE, users); }
function saveMessages() { writeJSON(MESSAGES_FILE, messages); }

// ========== INIT ADMIN ACCOUNT ==========
async function initAdmin() {
  if (!users['admin']) {
    const hash = await bcrypt.hash('admin123', 10);
    users['admin'] = {
      username: 'admin',
      fullName: 'Admin',
      passwordHash: hash,
      role: 'admin',
      publicKey: null,          // set on first login from browser
      encryptedPrivateKey: null,
      keySalt: null,
      keyIv: null,
      createdAt: new Date().toISOString()
    };
    saveUsers();
    console.log('Admin account created (admin / admin123)');
  }
}

// ========== MIDDLEWARE ==========
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Simple token auth
const tokens = new Map(); // token -> username

function authMiddleware(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !tokens.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  req.username = tokens.get(token);
  req.user = users[req.username];
  next();
}

// ========== AUTH ROUTES ==========
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, fullName, publicKey, encryptedPrivateKey, keySalt, keyIv } = req.body;

    if (!username || !password || !fullName) return res.status(400).json({ error: 'All fields required' });
    if (username.length < 3) return res.status(400).json({ error: 'Username min 3 chars' });
    if (!/^[a-z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: lowercase, numbers, underscores only' });
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
    if (users[username]) return res.status(400).json({ error: 'Username already taken' });

    const hash = await bcrypt.hash(password, 10);
    users[username] = {
      username, fullName,
      passwordHash: hash,
      role: 'client',
      publicKey: publicKey || null,
      encryptedPrivateKey: encryptedPrivateKey || null,
      keySalt: keySalt || null,
      keyIv: keyIv || null,
      createdAt: new Date().toISOString()
    };
    saveUsers();

    // Auto welcome message from admin (encrypted later client-side, placeholder here)
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
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields required' });

    const user = users[username.toLowerCase()];
    if (!user) return res.status(400).json({ error: 'Account not found' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(400).json({ error: 'Incorrect password' });

    const token = uuidv4();
    tokens.set(token, user.username);

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

// Update user keys (needed for admin first login and key rotation)
app.post('/api/update-keys', authMiddleware, (req, res) => {
  const { publicKey, encryptedPrivateKey, keySalt, keyIv } = req.body;
  users[req.username].publicKey = publicKey;
  users[req.username].encryptedPrivateKey = encryptedPrivateKey;
  users[req.username].keySalt = keySalt;
  users[req.username].keyIv = keyIv;
  saveUsers();
  res.json({ success: true });
});

// ========== API ROUTES ==========
app.get('/api/contacts', authMiddleware, (req, res) => {
  const contactList = [];
  if (req.user.role === 'admin') {
    // Admin sees all clients
    for (const u of Object.values(users)) {
      if (u.role === 'client') contactList.push(sanitizeUser(u));
    }
  } else {
    // Client sees only admin
    if (users['admin']) contactList.push(sanitizeUser(users['admin']));
  }
  res.json(contactList);
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

app.get('/api/publickey/:username', authMiddleware, (req, res) => {
  const user = users[req.params.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ publicKey: user.publicKey });
});

// Media upload (encrypted blob)
const upload = multer({
  storage: multer.diskStorage({
    destination: MEDIA_DIR,
    filename: (req, file, cb) => cb(null, uuidv4() + '.enc')
  }),
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.post('/api/upload', authMiddleware, upload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ mediaId: req.file.filename });
});

app.get('/api/media/:id', authMiddleware, (req, res) => {
  const filePath = path.join(MEDIA_DIR, req.params.id);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
  res.sendFile(filePath);
});

// ========== SOCKET.IO ==========
const onlineUsers = new Map(); // username -> socket.id

io.on('connection', (socket) => {
  let socketUser = null;

  socket.on('authenticate', (token) => {
    const username = tokens.get(token);
    if (!username) return socket.emit('auth_error', 'Invalid token');
    socketUser = username;
    onlineUsers.set(username, socket.id);
    io.emit('user_online', { username, online: true });
    // Send online users list
    socket.emit('online_users', Array.from(onlineUsers.keys()));
  });

  socket.on('send_message', (msg) => {
    if (!socketUser) return;
    const message = {
      id: uuidv4(),
      from: socketUser,
      to: msg.to,
      type: msg.type || 'text',
      encrypted: msg.encrypted,
      encKeyForSender: msg.encKeyForSender,
      encKeyForRecipient: msg.encKeyForRecipient,
      mediaId: msg.mediaId || null,
      mediaType: msg.mediaType || null,
      mediaName: msg.mediaName || null,
      timestamp: new Date().toISOString()
    };
    messages.push(message);
    saveMessages();

    // Send to recipient if online
    const recipientSocket = onlineUsers.get(msg.to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('new_message', message);
    }
    // Send back to sender for confirmation
    socket.emit('message_sent', message);
  });

  socket.on('typing', (data) => {
    if (!socketUser) return;
    const recipientSocket = onlineUsers.get(data.to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('user_typing', { from: socketUser });
    }
  });

  socket.on('stop_typing', (data) => {
    if (!socketUser) return;
    const recipientSocket = onlineUsers.get(data.to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('user_stop_typing', { from: socketUser });
    }
  });

  socket.on('disconnect', () => {
    if (socketUser) {
      onlineUsers.delete(socketUser);
      io.emit('user_online', { username: socketUser, online: false });
    }
  });
});

// ========== HELPERS ==========
function sanitizeUser(u) {
  return {
    username: u.username,
    fullName: u.fullName,
    role: u.role,
    publicKey: u.publicKey,
    createdAt: u.createdAt
  };
}

// ========== START ==========
initAdmin().then(() => {
  server.listen(PORT, () => {
    console.log(`SmartChatOnly running on port ${PORT}`);
    console.log(`Admin login: admin / admin123`);
  });
});
