const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const Redis = require('ioredis');
const rateLimit = require('express-rate-limit');

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
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // 100 request per IP
  message: { error: '⛔ Terlalu banyak request. Coba lagi nanti.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// ===== AUTO BLOCK IP (Brute Force Protection) =====
const blockedIPs = new Map(); // IP → { attempts, blockUntil }

async function checkBlocked(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  
  const blockData = blockedIPs.get(ip);
  if (blockData && blockData.blockUntil > Date.now()) {
    return res.status(403).json({ 
      error: '⛔ IP diblokir sementara. Coba lagi nanti.',
      blockUntil: new Date(blockData.blockUntil).toISOString()
    });
  }
  
  // Log request (untuk deteksi mencurigakan)
  console.log(`[${new Date().toISOString()}] ${ip} - ${req.method} ${req.path}`);
  
  next();
}

app.use(checkBlocked);

// ===== MIDDLEWARE CEK SESSION =====
async function checkSession(req, res, next) {
  try {
    const sessionId = req.cookies.sessionId;
    
    if (!sessionId) {
      return res.status(401).json({ 
        error: 'NO_SESSION',
        message: 'Belum login atau session expired.'
      });
    }
    
    const sessionData = await redis.get(`session:${sessionId}`);
    if (!sessionData) {
      res.clearCookie('sessionId');
      return res.status(401).json({ 
        error: 'SESSION_EXPIRED',
        message: 'Session expired. Silahkan login ulang.'
      });
    }
    
    req.session = JSON.parse(sessionData);
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
    console.error('❌ Captcha error:', error.message);
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
    
    // Cek captcha
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
      // Tambahin attempt gagal
      const blockData = blockedIPs.get(ip) || { attempts: 0, blockUntil: 0 };
      blockData.attempts += 1;
      
      if (blockData.attempts >= 5) {
        blockData.blockUntil = Date.now() + 300000; // 5 menit
        blockedIPs.set(ip, blockData);
        return res.status(429).json({ 
          error: '⛔ Terlalu banyak percobaan. IP diblokir 5 menit.',
          blockUntil: new Date(blockData.blockUntil).toISOString()
        });
      }
      
      blockedIPs.set(ip, blockData);
      return res.status(400).json({ error: 'Captcha salah! Coba lagi.' });
    }
    
    // Reset attempts kalo berhasil
    blockedIPs.delete(ip);
    
    // Generate session (7 hari)
    const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
    const expiresIn = 7 * 24 * 3600; // 7 hari
    
    await redis.setex(`session:${sessionId}`, expiresIn, JSON.stringify({
      username: telegramUsername,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString()
    }));
    
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: expiresIn * 1000
    });
    
    res.json({ success: true, message: '✅ Verifikasi berhasil! Session 7 hari.' });
  } catch (error) {
    console.error('❌ Verify error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ===== CEK SESSION (Auto-check) =====
app.get('/api/check-session', async (req, res) => {
  try {
    const sessionId = req.cookies.sessionId;
    
    if (!sessionId) {
      return res.json({ 
        valid: false, 
        error: 'NO_SESSION',
        message: 'Belum login' 
      });
    }
    
    const sessionData = await redis.get(`session:${sessionId}`);
    if (!sessionData) {
      res.clearCookie('sessionId');
      return res.json({ 
        valid: false, 
        error: 'SESSION_EXPIRED',
        message: 'Session expired' 
      });
    }
    
    const session = JSON.parse(sessionData);
    res.json({ 
      valid: true, 
      username: session.username,
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
    
    const newMessage = {
      id: Date.now().toString(36) + Math.random().toString(36).substr(2, 4),
      username: req.session.username,
      message: message,
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
