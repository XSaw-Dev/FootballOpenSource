const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { createClient } = require('@vercel/redis');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ===== KONEKSI REDIS (PAKE CREDENTIAL LU) =====
const redis = createClient({
  url: 'redis://default:gQAAAAAAAokGAAIgcDJmZTA5NTM5OTJkNzQ0NjJiOTIxNzUyMzZlMTg4ZGNlMA@cosmic-moose-166150.upstash.io:6379'
});

redis.on('error', (err) => console.error('❌ Redis Error:', err));
redis.on('connect', () => console.log('✅ Redis Connected!'));

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
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== VERIFIKASI CAPTCHA + USERNAME =====
app.post('/api/verify', async (req, res) => {
  try {
    const { captchaId, answer, telegramUsername } = req.body;
    
    if (!captchaId || !answer || !telegramUsername) {
      return res.status(400).json({ error: 'Semua field wajib diisi!' });
    }
    
    const correctAnswer = await redis.get(`captcha:${captchaId}`);
    if (!correctAnswer || correctAnswer !== answer.toString()) {
      return res.status(400).json({ error: 'Captcha salah! Coba lagi.' });
    }
    
    // Generate session cookie (1 jam)
    const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
    
    await redis.setex(`session:${sessionId}`, 3600, JSON.stringify({
      username: telegramUsername,
      createdAt: new Date().toISOString()
    }));
    
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000
    });
    
    res.json({ success: true, message: 'Verifikasi berhasil!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== MIDDLEWARE CEK SESSION =====
async function checkSession(req, res, next) {
  try {
    const sessionId = req.cookies.sessionId;
    if (!sessionId) {
      return res.status(401).json({ error: 'Session expired atau belum login.' });
    }
    
    const sessionData = await redis.get(`session:${sessionId}`);
    if (!sessionData) {
      return res.status(401).json({ error: 'Session expired. Verifikasi ulang.' });
    }
    
    req.session = JSON.parse(sessionData);
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

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
app.post('/api/logout', (req, res) => {
  res.clearCookie('sessionId');
  res.json({ success: true, message: 'Logout berhasil.' });
});

// ===== TEST REDIS =====
app.get('/api/ping', async (req, res) => {
  try {
    await redis.ping();
    res.json({ status: '✅ Redis Connected!' });
  } catch (error) {
    res.status(500).json({ status: '❌ Redis Error', error: error.message });
  }
});

module.exports = app;
