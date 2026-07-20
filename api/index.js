// ================================================================
// MAIN ENTRY - api/index.js
// ================================================================
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');

// ===== IMPORT MODULES =====
const redis = require('./modules/redis');
const { 
  wafMiddleware, 
  generalLimiter, 
  loginLimiter, 
  chatLimiter 
} = require('./modules/waf');
const {
  checkSession, checkDeveloper,
  generateCaptcha, verifyCaptcha,
  developerLogin, checkSessionAPI, logout,
  getRealIP
} = require('./modules/auth');
const {
  sendMessage, getMessages, clearMessages,
  typing, getTypingUsers, getOnlineUsers
} = require('./modules/chat');
const {
  getIPList, banIP, unbanIP, deleteIP,
  getWAFStats, testSecurity
} = require('./modules/admin');

const app = express();

// ===== MIDDLEWARE =====
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// ===== WAF + RATE LIMIT =====
app.use(wafMiddleware);
app.use('/api/', generalLimiter);
app.use('/api/verify', loginLimiter);
app.use('/api/chat/send', chatLimiter);

// ===== AUTH ROUTES =====
app.get('/api/captcha', generateCaptcha);
app.post('/api/verify', verifyCaptcha);
app.post('/api/developer-login', developerLogin);
app.get('/api/check-session', checkSessionAPI);
app.post('/api/logout', logout);

// ===== CHAT ROUTES =====
app.post('/api/chat/send', checkSession, sendMessage);
app.get('/api/chat/messages', checkSession, getMessages);
app.delete('/api/chat/clear', checkDeveloper, clearMessages);
app.post('/api/typing', checkSession, typing);
app.get('/api/typing-users', checkSession, getTypingUsers);
app.get('/api/online-users', checkSession, getOnlineUsers);

// ===== ADMIN ROUTES =====
app.get('/api/ip-list', checkDeveloper, getIPList);
app.post('/api/ban-ip', checkDeveloper, banIP);
app.post('/api/unban-ip', checkDeveloper, unbanIP);
app.delete('/api/delete-ip', checkDeveloper, deleteIP);
app.get('/api/waf-stats', checkDeveloper, getWAFStats);
app.get('/api/test-security', checkDeveloper, testSecurity);

// ===== TEST REDIS =====
app.get('/api/ping', async (req, res) => {
  try {
    const pong = await redis.ping();
    res.json({ status: '✅ Redis Connected!', pong });
  } catch (error) {
    res.status(500).json({ status: '❌ Redis Error', error: error.message });
  }
});

// ================================================================
// 404 HANDLER - PASTIKAN JSON
// ================================================================
app.use((req, res) => {
  res.status(404).json({ 
    error: 'NOT_FOUND', 
    message: 'Endpoint tidak ditemukan.',
    path: req.path 
  });
});

// ================================================================
// GLOBAL ERROR HANDLER - PASTIKAN JSON
// ================================================================
app.use((err, req, res, next) => {
  console.error('❌ Global error:', err.message);
  console.error('Stack:', err.stack);
  
  // Pastiin response JSON, bukan HTML
  res.status(500).json({ 
    error: 'INTERNAL_ERROR', 
    message: 'Terjadi kesalahan server.',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

module.exports = app;
