const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const Redis = require('ioredis');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

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

// ===== LOAD DEVELOPER DATA =====
function getDeveloperData() {
  try {
    const data = fs.readFileSync(path.join(__dirname, 'developer.json'), 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return { username: 'I7ZX', password: 'GueYangBikin' };
  }
}

// ===== BAN SYSTEM =====
const bannedIPs = new Map();
const ipHistory = new Map();

async function checkBan(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  
  const redisBan = await redis.get(`ban:${ip}`);
  if (redisBan) {
    const banData = JSON.parse(redisBan);
    return res.status(403).json({ 
      error: '⛔ IP Anda diblokir oleh administrator.',
      bannedAt: banData.bannedAt,
      reason: banData.reason || 'Diblokir oleh admin'
    });
  }
  
  if (bannedIPs.has(ip)) {
    return res.status(403).json({ 
      error: '⛔ IP Anda diblokir oleh administrator.',
      bannedAt: bannedIPs.get(ip).bannedAt
    });
  }
  
  const history = ipHistory.get(ip) || { firstSeen: new Date().toISOString(), attempts: 0 };
  history.lastSeen = new Date().toISOString();
  history.attempts += 1;
  ipHistory.set(ip, history);
  await redis.setex(`ip:${ip}`, 2592000, JSON.stringify(history));
  
  next();
}
app.use(checkBan);

// ===== GENERATE SESSION SIGNATURE (TANPA SECRET KEY) =====
function generateSessionSignature(username, ip, userAgent, timestamp) {
  // Kombinasi: username + IP + user-agent + timestamp → hash
  const raw = `${username}|${ip}|${userAgent}|${timestamp}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// ===== MIDDLEWARE CEK SESSION (DIPERKETAT) =====
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
    
    const session = JSON.parse(sessionData);
    const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || '';
    
    // VALIDASI 1: IP harus sama dengan saat login
    if (session.ip && session.ip !== ip) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'IP_MISMATCH', message: 'IP berbeda dengan session.' });
    }
    
    // VALIDASI 2: User-Agent harus sama
    if (session.userAgent && session.userAgent !== userAgent) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'DEVICE_MISMATCH', message: 'Device berbeda.' });
    }
    
    // VALIDASI 3: Signature harus valid
    const expectedSignature = generateSessionSignature(
      session.username,
      session.ip,
      session.userAgent,
      session.timestamp
    );
    if (session.signature !== expectedSignature) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'INVALID_SIGNATURE', message: 'Signature tidak valid.' });
    }
    
    req.session = session;
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

// ===== MIDDLEWARE CEK DEVELOPER (DOUBLE VALIDATION) =====
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
    const developer = getDeveloperData();
    const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || '';
    
    // VALIDASI DEVELOPER
    if (!session.isDeveloper || session.username !== developer.username) {
      return res.status(403).json({ error: 'Akses ditolak. Hanya untuk developer.' });
    }
    
    // Validasi IP
    if (session.ip && session.ip !== ip) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'IP_MISMATCH' });
    }
    
    // Validasi User-Agent
    if (session.userAgent && session.userAgent !== userAgent) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'DEVICE_MISMATCH' });
    }
    
    // Validasi Signature
    const expectedSignature = generateSessionSignature(
      session.username,
      session.ip,
      session.userAgent,
      session.timestamp
    );
    if (session.signature !== expectedSignature) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'INVALID_SIGNATURE' });
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
  const userAgent = req.headers['user-agent'] || '';
  
  try {
    const { captchaId, answer, telegramUsername } = req.body;
    
    if (!captchaId || !answer || !telegramUsername) {
      return res.status(400).json({ error: 'Semua field wajib diisi!' });
    }
    
    const redisBan = await redis.get(`ban:${ip}`);
    if (redisBan) {
      return res.status(403).json({ error: '⛔ IP Anda diblokir oleh administrator.' });
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
      const history = await redis.get(`ip:${ip}`);
      if (history) {
        const data = JSON.parse(history);
        data.attempts = (data.attempts || 0) + 1;
        await redis.setex(`ip:${ip}`, 2592000, JSON.stringify(data));
        
        if (data.attempts >= 5) {
          await redis.setex(`ban:${ip}`, 3600, JSON.stringify({
            bannedAt: new Date().toISOString(),
            reason: 'Terlalu banyak percobaan gagal (auto-ban)'
          }));
          return res.status(429).json({ error: '⛔ IP diblokir sementara 1 jam.' });
        }
      }
      
      return res.status(400).json({ error: 'Captcha salah! Coba lagi.' });
    }
    
    const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
    const expiresIn = 7 * 24 * 3600;
    const timestamp = Date.now();
    
    const developer = getDeveloperData();
    const isDeveloper = telegramUsername.toLowerCase() === developer.username.toLowerCase();
    
    // Generate signature tanpa secret key
    const signature = generateSessionSignature(telegramUsername, ip, userAgent, timestamp);
    
    const sessionData = {
      username: telegramUsername,
      isDeveloper: isDeveloper,
      ip: ip,
      userAgent: userAgent,
      timestamp: timestamp,
      signature: signature,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString()
    };
    
    await redis.setex(`session:${sessionId}`, expiresIn, JSON.stringify(sessionData));
    
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
  const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'] || '';
  
  try {
    const { username, password } = req.body;
    const developer = getDeveloperData();
    
    if (username === developer.username && password === developer.password) {
      const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
      const expiresIn = 7 * 24 * 3600;
      const timestamp = Date.now();
      
      const signature = generateSessionSignature(username, ip, userAgent, timestamp);
      
      const sessionData = {
        username: username,
        isDeveloper: true,
        isDeveloperLogin: true,
        ip: ip,
        userAgent: userAgent,
        timestamp: timestamp,
        signature: signature,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString()
      };
      
      await redis.setex(`session:${sessionId}`, expiresIn, JSON.stringify(sessionData));
      
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
    const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || '';
    
    // Validasi cepat
    if (session.ip && session.ip !== ip) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.json({ valid: false, error: 'IP_MISMATCH' });
    }
    
    if (session.userAgent && session.userAgent !== userAgent) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.json({ valid: false, error: 'DEVICE_MISMATCH' });
    }
    
    res.json({ 
      valid: true, 
      username: session.username,
      isDeveloper: session.isDeveloper || false,
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

// ===== CLEAR MESSAGES =====
app.delete('/api/chat/clear', checkDeveloper, async (req, res) => {
  try {
    const chatKey = 'chat:global';
    await redis.del(chatKey);
    res.json({ success: true, message: '✅ Semua pesan berhasil dihapus!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== GET IP LIST =====
app.get('/api/ip-list', checkDeveloper, async (req, res) => {
  try {
    const keys = await redis.keys('ip:*');
    const ips = [];
    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const ip = key.replace('ip:', '');
        const info = JSON.parse(data);
        const ban = await redis.get(`ban:${ip}`);
        ips.push({
          ip: ip,
          firstSeen: info.firstSeen,
          lastSeen: info.lastSeen,
          attempts: info.attempts || 0,
          isBanned: !!ban,
          banData: ban ? JSON.parse(ban) : null
        });
      }
    }
    // Sort by lastSeen descending
    ips.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
    res.json({ success: true, ips });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== BAN IP =====
app.post('/api/ban-ip', checkDeveloper, async (req, res) => {
  try {
    const { ip, reason } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP wajib diisi!' });
    }
    
    await redis.setex(`ban:${ip}`, 2592000, JSON.stringify({
      bannedAt: new Date().toISOString(),
      reason: reason || 'Diblokir oleh admin'
    }));
    
    res.json({ success: true, message: `✅ IP ${ip} berhasil diblokir.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== UNBAN IP =====
app.post('/api/unban-ip', checkDeveloper, async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP wajib diisi!' });
    }
    
    await redis.del(`ban:${ip}`);
    res.json({ success: true, message: `✅ IP ${ip} berhasil di-unblokir.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== DELETE IP FROM HISTORY =====
app.delete('/api/delete-ip', checkDeveloper, async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP wajib diisi!' });
    }
    
    // Cek apakah IP diban
    const isBanned = await redis.get(`ban:${ip}`);
    if (isBanned) {
      return res.status(400).json({ 
        error: 'IP ini masih diban. Unban dulu sebelum menghapus dari history.',
        isBanned: true
      });
    }
    
    await redis.del(`ip:${ip}`);
    ipHistory.delete(ip);
    res.json({ success: true, message: `✅ IP ${ip} berhasil dihapus dari history.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== TEST SECURITY =====
app.get('/api/test-security', checkDeveloper, async (req, res) => {
  try {
    const keys = await redis.keys('ip:*');
    const banKeys = await redis.keys('ban:*');
    
    res.json({
      success: true,
      message: '✅ Security Gateway berfungsi normal!',
      session: req.session,
      totalIPs: keys.length,
      totalBanned: banKeys.length,
      blockedIPs: await Promise.all(banKeys.map(async (key) => {
        const ip = key.replace('ban:', '');
        const data = await redis.get(key);
        return { ip, data: JSON.parse(data) };
      }))
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== TYPING =====
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

app.get('/api/typing-users', checkSession, async (req, res) => {
  try {
    const typingKey = 'typing:users';
    const typingUsers = await redis.smembers(typingKey);
    res.json({ success: true, typingUsers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== ONLINE USERS =====
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

module.exports = app;
