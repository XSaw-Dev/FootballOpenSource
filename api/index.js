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

// ================================================================
// 1. BAN SYSTEM + AUTO REDIRECT
// ================================================================

// ===== MIDDLEWARE BAN REDIRECT =====
async function banRedirect(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  
  // Cek di Redis
  const redisBan = await redis.get(`ban:${ip}`);
  if (redisBan) {
    const banData = JSON.parse(redisBan);
    const attempts = await redis.get(`ip:${ip}`);
    const attemptData = attempts ? JSON.parse(attempts) : { attempts: 0 };
    
    // Hitung risk
    let risk = Math.min(20 + (attemptData.attempts || 0) * 12, 95);
    if (banData.reason && banData.reason.includes('admin')) risk = 90;
    
    const redirectUrl = `/ban.html?ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent(banData.reason || 'Diblokir oleh admin')}&attempts=${attemptData.attempts || 0}&risk=${risk}&bannedAt=${encodeURIComponent(banData.bannedAt)}&status=BANNED`;
    
    // Kalo request API, kasih JSON
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({
        error: 'BANNED',
        message: 'IP Anda telah diblokir',
        redirect: redirectUrl
      });
    }
    
    // Kalo request HTML, redirect
    return res.redirect(redirectUrl);
  }
  
  next();
}

// PAKAI MIDDLEWARE INI SEBELUM ROUTE LAIN
app.use(banRedirect);

// ================================================================
// 2. GENERATE SESSION SIGNATURE (TANPA SECRET KEY)
// ================================================================

function generateSessionSignature(username, ip, userAgent, timestamp) {
  const raw = `${username}|${ip}|${userAgent}|${timestamp}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// ================================================================
// 3. MIDDLEWARE CEK SESSION (DIPERKETAT)
// ================================================================

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

// ================================================================
// 4. MIDDLEWARE CEK DEVELOPER (DIPERKETAT)
// ================================================================

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

// ================================================================
// 5. GENERATE CAPTCHA
// ================================================================

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

// ================================================================
// 6. VERIFIKASI CAPTCHA + USERNAME (DENGAN AUTO-BAN)
// ================================================================

app.post('/api/verify', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'] || '';
  
  try {
    const { captchaId, answer, telegramUsername } = req.body;
    
    if (!captchaId || !answer || !telegramUsername) {
      return res.status(400).json({ error: 'Semua field wajib diisi!' });
    }
    
    // CEK BAN DULU
    const redisBan = await redis.get(`ban:${ip}`);
    if (redisBan) {
      const banData = JSON.parse(redisBan);
      return res.status(403).json({ 
        error: 'BANNED',
        message: 'IP Anda telah diblokir',
        redirect: `/ban.html?ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent(banData.reason || 'Diblokir oleh admin')}`
      });
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
      // Update attempts
      const history = await redis.get(`ip:${ip}`);
      let attemptData = history ? JSON.parse(history) : { firstSeen: new Date().toISOString(), attempts: 0 };
      attemptData.attempts = (attemptData.attempts || 0) + 1;
      attemptData.lastSeen = new Date().toISOString();
      
      await redis.setex(`ip:${ip}`, 2592000, JSON.stringify(attemptData));
      
      // AUTO-BAN KALO 5 ATTEMPTS
      if (attemptData.attempts >= 5) {
        await redis.setex(`ban:${ip}`, 2592000, JSON.stringify({
          bannedAt: new Date().toISOString(),
          reason: 'Terlalu banyak percobaan login gagal (auto-ban)'
        }));
        return res.status(429).json({ 
          error: 'AUTO_BANNED',
          message: 'IP Anda diblokir otomatis karena terlalu banyak percobaan gagal.',
          redirect: `/ban.html?ip=${encodeURIComponent(ip)}&reason=Terlalu banyak percobaan login gagal (auto-ban)&attempts=${attemptData.attempts}&risk=85&bannedAt=${new Date().toISOString()}`
        });
      }
      
      return res.status(400).json({ error: 'Captcha salah! Coba lagi.' });
    }
    
    // Reset attempts kalo berhasil
    await redis.del(`ip:${ip}`);
    
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

// ================================================================
// 7. DEVELOPER LOGIN
// ================================================================

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

// ================================================================
// 8. CEK SESSION
// ================================================================

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

// ================================================================
// 9. KIRIM PESAN
// ================================================================

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

// ================================================================
// 10. AMBIL PESAN
// ================================================================

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

// ================================================================
// 11. CLEAR MESSAGES (Developer Only)
// ================================================================

app.delete('/api/chat/clear', checkDeveloper, async (req, res) => {
  try {
    const chatKey = 'chat:global';
    await redis.del(chatKey);
    res.json({ success: true, message: '✅ Semua pesan berhasil dihapus!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 12. IP CONTROL (Developer Only)
// ================================================================

// GET IP LIST
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
    ips.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
    res.json({ success: true, ips });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// BAN IP
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

// UNBAN IP
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

// DELETE IP FROM HISTORY
app.delete('/api/delete-ip', checkDeveloper, async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP wajib diisi!' });
    }
    
    const isBanned = await redis.get(`ban:${ip}`);
    if (isBanned) {
      return res.status(400).json({ 
        error: 'IP ini masih diban. Unban dulu sebelum menghapus dari history.',
        isBanned: true
      });
    }
    
    await redis.del(`ip:${ip}`);
    res.json({ success: true, message: `✅ IP ${ip} berhasil dihapus dari history.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 13. TEST SECURITY (Developer Only)
// ================================================================

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

// ================================================================
// 14. TYPING INDICATOR
// ================================================================

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

// ================================================================
// 15. ONLINE USERS
// ================================================================

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

// ================================================================
// 16. LOGOUT
// ================================================================

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

// ================================================================
// 17. TEST REDIS (Opsional)
// ================================================================

app.get('/api/ping', async (req, res) => {
  try {
    const pong = await redis.ping();
    res.json({ status: '✅ Redis Connected!', pong });
  } catch (error) {
    res.status(500).json({ status: '❌ Redis Error', error: error.message });
  }
});

module.exports = app;
