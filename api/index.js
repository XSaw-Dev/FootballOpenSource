const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { createClient } = require('@vercel/redis');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const redis = createClient({
  url: process.env.REDIS_URL
});

// ===== GENERATE CAPTCHA =====
app.get('/api/captcha', async (req, res) => {
  const captchaId = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
  const num1 = Math.floor(Math.random() * 10) + 1;
  const num2 = Math.floor(Math.random() * 10) + 1;
  const answer = num1 + num2;
  
  await redis.setex(`captcha:${captchaId}`, 300, answer.toString()); // 5 menit expired
  
  res.json({
    captchaId,
    question: `${num1} + ${num2} = ?`,
    image: null // Bisa diganti pake gambar custom kalo mau
  });
});

// ===== VERIFIKASI CAPTCHA + USERNAME =====
app.post('/api/verify', async (req, res) => {
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
  const expiresAt = Date.now() + 3600000; // 1 jam
  
  await redis.setex(`session:${sessionId}`, 3600, JSON.stringify({
    username: telegramUsername,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(expiresAt).toISOString()
  }));
  
  res.cookie('sessionId', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000 // 1 jam
  });
  
  res.json({ success: true, message: 'Verifikasi berhasil! Selamat datang.' });
});

// ===== CEK SESSION (Middleware) =====
async function checkSession(req, res, next) {
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
}

// ===== KIRIM PESAN =====
app.post('/api/chat/send', checkSession, async (req, res) => {
  const { message } = req.body;
  if (!message || message.length > 500) {
    return res.status(400).json({ error: 'Pesan maksimal 500 karakter.' });
  }
  
  const chatId = 'global';
  const chatKey = `chat:${chatId}`;
  const chatData = await redis.lrange(chatKey, 0, -1);
  
  const newMessage = {
    id: Date.now().toString(36) + Math.random().toString(36).substr(2, 4),
    username: req.session.username,
    message: message,
    timestamp: new Date().toISOString()
  };
  
  // Simpan ke Redis, auto-expire 1 jam
  await redis.rpush(chatKey, JSON.stringify(newMessage));
  await redis.expire(chatKey, 3600); // 1 jam auto-delete
  
  res.json({ success: true, message: newMessage });
});

// ===== AMBIL PESAN =====
app.get('/api/chat/messages', checkSession, async (req, res) => {
  const chatKey = 'chat:global';
  const messages = await redis.lrange(chatKey, 0, -1);
  
  res.json({
    success: true,
    messages: messages.map(msg => JSON.parse(msg)),
    count: messages.length
  });
});

// ===== LOGOUT (Hapus Cookie) =====
app.post('/api/logout', (req, res) => {
  res.clearCookie('sessionId');
  res.json({ success: true, message: 'Logout berhasil.' });
});

module.exports = app;
