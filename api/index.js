const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const Redis = require('ioredis');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ===== KONEKSI REDIS =====
const redis = new Redis({
  host: 'cosmic-moose-166150.upstash.io',
  port: 6379,
  password: 'gQAAAAAAAokGAAIgcDJmZTA5NTM5OTJkNzQ0NjJiOTIxNzUyMzZlMTg4ZGNlMA',
  tls: {},
  retryStrategy: (times) => Math.min(times * 50, 2000)
});

redis.on('error', (err) => console.error('❌ Redis Error:', err));
redis.on('connect', () => console.log('✅ Redis Connected!'));

// ===== RATE LIMITER =====
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: '⛔ Terlalu banyak request. Coba lagi nanti.' }
});
app.use('/api/', limiter);

// ===== AUTO BLOCK IP =====
const blockedIPs = new Map();

async function checkBlocked(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  const blockData = blockedIPs.get(ip);
  
  if (blockData && blockData.blockUntil > Date.now()) {
    return res.status(403).json({ 
      error: '⛔ IP diblokir sementara.',
      blockUntil: new Date(blockData.blockUntil).toISOString()
    });
  }
  
  next();
}
app.use(checkBlocked);

// ===== LOAD DEVELOPER DATA =====
function getDeveloperData() {
  try {
    const data = fs.readFileSync(path.join(__dirname, 'developer.json'), 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return { username: 'I7ZX', password: 'GueYangBikin' };
  }
}

// ===== MIDDLEWARE CEK SESSION =====
async function checkSession(req, res, next) {
  try {
    const sessionId = req.cookies.sessionId;
    if (!sessionId) {
      return res.status(401).json({ error: 'NO_SESSION', message: 'Belum login.' });
    }
    
    const sessionData = await redis.get(`session:${sessionId}`);
    if (!sessionData) {
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'SESSION_EXPIRED', message: 'Session expired.' });
    }
    
    req.session = JSON.parse(sessionData);
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

// ===== MIDDLEWARE CEK DEVELOPER =====
async function checkDeveloper(req, res, next) {
  try {
    const sessionId = req.cookies.sessionId;
    if (!sessionId) {
      return res.status(401).json({ error: 'NO_SESSION' });
    }
    
    const sessionData = await redis.get(`session:${sessionId}`);
    if (!sessionData) {
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'SESSION_EXPIRED' });
    }
    
    const session = JSON.parse(sessionData);
    if (!session.isDeveloper) {
      return res.status(403).json({ error: 'Akses ditolak. Hanya untuk developer.' });
    }
    
    req.session = session;
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

// ===== GENERATE CAPTCHA =====
app.get('/api/captcha', async (req, res) => {
  try {
    const captchaId = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const answer = num1 + num2;
    
    await redis.setex(`captcha:${captchaId}`, 300, answer.toString());
    
    res.json({
      success: true,
      captchaId,
      question: `${num1} + ${num2} = ?`
    });
  } catch (error) {
    res.json({
      success: true,
      captchaId: 'fallback-' + Date.now(),
      question: '3 + 4 = ?'
    });
  }
});

// ===== VERIFIKASI CAPTCHA + USERNAME =====
app.post('/api/verify', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  
  try {
    const { captchaId, answer, telegramUsername } = req.body;
    
    if (!captchaId || !answer || !telegramUsername) {
      return res.status(400).json({ error: 'Semua field wajib diisi!' });
    }
    
    let verified = false;
    if (captchaId.startsWith('fallback-')) {
      verified = true;
    } else {
      const correctAnswer = await redis.get(`captcha:${captchaId}`);
      if (correctAnswer && correctAnswer === answer.toString()) {
        verified = true;
      }
    }
    
    if (!verified) {
      const blockData = blockedIPs.get(ip) || { attempts: 0, blockUntil: 0 };
      blockData.attempts += 1;
      
      if (blockData.attempts >= 5) {
        blockData.blockUntil = Date.now() + 300000;
        blockedIPs.set(ip, blockData);
        return res.status(429).json({ error: '⛔ IP diblokir 5 menit.' });
      }
      
      blockedIPs.set(ip, blockData);
      return res.status(400).json({ error: 'Captcha salah! Coba lagi.' });
    }
    
    blockedIPs.delete(ip);
    
    const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
    const expiresIn = 7 * 24 * 3600;
    
    // Cek apakah user adalah developer
    const developer = getDeveloperData();
    const isDeveloper = telegramUsername.toLowerCase() === developer.username.toLowerCase();
    
    await redis.setex(`session:${sessionId}`, expiresIn, JSON.stringify({
      username: telegramUsername,
      isDeveloper: isDeveloper,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString()
    }));
    
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: expiresIn * 1000
    });
    
    res.json({ 
      success: true, 
      message: '✅ Verifikasi berhasil!',
      isDeveloper: isDeveloper
    });
  } catch (error) {
    console.error('❌ Verify error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ===== DEVELOPER LOGIN =====
app.post('/api/developer-login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const developer = getDeveloperData();
    
    if (username === developer.username && password === developer.password) {
      const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
      const expiresIn = 7 * 24 * 3600;
      
      await redis.setex(`session:${sessionId}`, expiresIn, JSON.stringify({
        username: username,
        isDeveloper: true,
        isDeveloperLogin: true,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString()
      }));
      
      res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: expiresIn * 1000
      });
      
      res.json({ success: true, isDeveloper: true });
    } else {
      res.status(401).json({ error: 'Username atau password salah!' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== CEK SESSION =====
app.get('/api/check-session', async (req, res) => {
  try {
    const sessionId = req.cookies.sessionId;
    
    if (!sessionId) {
      return res.json({ valid: false, error: 'NO_SESSION' });
    }
    
    const sessionData = await redis.get(`session:${sessionId}`);
    if (!sessionData) {
      res.clearCookie('sessionId');
      return res.json({ valid: false, error: 'SESSION_EXPIRED' });
    }
    
    const session = JSON.parse(sessionData);
    res.json({ 
      valid: true, 
      username: session.username,
      isDeveloper: session.isDeveloper || false,
      isDeveloperLogin: session.isDeveloperLogin || false,
      expiresAt: session.expiresAt
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== KIRIM PESAN =====
app.post('/api/chat/send', checkSession, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || message.length > 500) {
      return res.status(400).json({ error: 'Pesan maksimal 500 karakter.' });
    }
    
    const chatKey = 'chat:global';
    const isDeveloper = req.session.isDeveloper || false;
    
    const newMessage = {
      id: Date.now().toString(36) + Math.random().toString(36).substr(2, 4),
      username: req.session.username,
      message: message,
      isDeveloper: isDeveloper,
      timestamp: new Date().toISOString()
    };
    
    await redis.rpush(chatKey, JSON.stringify(newMessage));
    await redis.expire(chatKey, 3600);
    
    res.json({ success: true, message: newMessage });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== AMBIL PESAN =====
app.get('/api/chat/messages', checkSession, async (req, res) => {
  try {
    const chatKey = 'chat:global';
    const messages = await redis.lrange(chatKey, 0, -1);
    
    res.json({
      success: true,
      messages: messages.map(msg => JSON.parse(msg)),
      count: messages.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== CLEAR MESSAGES (HANYA DEVELOPER) =====
app.delete('/api/chat/clear', checkDeveloper, async (req, res) => {
  try {
    const chatKey = 'chat:global';
    await redis.del(chatKey);
    res.json({ success: true, message: '✅ Semua pesan berhasil dihapus!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== TYPING INDICATOR =====
app.post('/api/typing', checkSession, async (req, res) => {
  try {
    const { isTyping } = req.body;
    const typingKey = 'typing:users';
    const username = req.session.username;
    
    if (isTyping) {
      await redis.sadd(typingKey, username);
      await redis.expire(typingKey, 5);
    } else {
      await redis.srem(typingKey, username);
    }
    
    const typingUsers = await redis.smembers(typingKey);
    res.json({ success: true, typingUsers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== AMBIL TYPING USERS =====
app.get('/api/typing-users', checkSession, async (req, res) => {
  try {
    const typingKey = 'typing:users';
    const typingUsers = await redis.smembers(typingKey);
    res.json({ success: true, typingUsers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== LOGOUT =====
app.post('/api/logout', async (req, res) => {
  try {
    const sessionId = req.cookies.sessionId;
    if (sessionId) {
      await redis.del(`session:${sessionId}`);
    }
    res.clearCookie('sessionId');
    res.json({ success: true, message: 'Logout berhasil.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== TEST SECURITY GATEWAY (Developer Only) =====
app.get('/api/test-security', checkDeveloper, async (req, res) => {
  res.json({
    success: true,
    message: '✅ Security Gateway berfungsi normal!',
    session: req.session,
    blockedIPs: Array.from(blockedIPs.entries()).map(([ip, data]) => ({
      ip,
      attempts: data.attempts,
      blockUntil: new Date(data.blockUntil).toISOString()
    }))
  });
});

// ===== GET ONLINE USERS =====
app.get('/api/online-users', checkSession, async (req, res) => {
  try {
    const keys = await redis.keys('session:*');
    const users = [];
    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const session = JSON.parse(data);
        users.push(session.username);
      }
    }
    res.json({ success: true, users: [...new Set(users)] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = app;
