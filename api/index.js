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
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// ================================================================
// 1. REDIS CONNECTION
// ================================================================
const redis = new Redis({
  host: 'cosmic-moose-166150.upstash.io',
  port: 6379,
  password: 'gQAAAAAAAokGAAIgcDJmZTA5NTM5OTJkNzQ0NjJiOTIxNzUyMzZlMTg4ZGNlMA',
  tls: {},
  retryStrategy: (times) => Math.min(times * 50, 2000)
});

redis.on('error', (err) => console.error('❌ Redis Error:', err));
redis.on('connect', () => console.log('✅ Redis Connected!'));

// ================================================================
// 2. CONFIG
// ================================================================
const CONFIG = {
  SESSION_EXPIRY: 7 * 24 * 3600,
  CAPTCHA_EXPIRY: 300,
  MAX_MESSAGE_LENGTH: 500,
  MAX_ATTEMPTS: 5,
  BAN_EXPIRY: 2592000,
};

// ================================================================
// 3. GET REAL IP
// ================================================================
function getRealIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.headers['cf-connecting-ip'] ||
         req.ip ||
         '0.0.0.0';
}

// ================================================================
// 4. LOAD DEVELOPER DATA
// ================================================================
function getDeveloperData() {
  try {
    const data = fs.readFileSync(path.join(__dirname, 'developer.json'), 'utf8');
    return JSON.parse(data);
  } catch {
    return { username: 'I7ZX', password: 'GueYangBikin' };
  }
}

// ================================================================
// 5. RATE LIMITERS
// ================================================================
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: '⛔ Terlalu banyak request.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: '⛔ Terlalu banyak percobaan login.' }
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: '⛔ Terlalu banyak pesan.' }
});

app.use('/api/', generalLimiter);
app.use('/api/verify', loginLimiter);
app.use('/api/chat/send', chatLimiter);

// ================================================================
// 6. WAF - MALICIOUS PATTERNS
// ================================================================
const maliciousPatterns = [
  /(\bSELECT\b.*\bFROM\b|\bINSERT\b.*\bINTO\b|\bUPDATE\b.*\bSET\b|\bDELETE\b.*\bFROM\b|\bDROP\b.*\bTABLE\b)/i,
  /('.*\bOR\b.*'='|'.*\bAND\b.*'=')/i,
  /<script\b[^>]*>.*?<\/script>/i,
  /javascript\s*:/i,
  /\.\.\/|\.\.\\/,
  /;\s*rm\s+-rf\s+\//i,
  /bot|crawler|spider|scraper|curl|wget|python|java|php|ruby|perl|go|nmap|sqlmap/i,
];

function detectMalicious(req) {
  const data = JSON.stringify(req.body || {}) + JSON.stringify(req.query || {}) + (req.headers['user-agent'] || '');
  for (const pattern of maliciousPatterns) {
    if (pattern.test(data)) {
      return { isMalicious: true, pattern: pattern.source };
    }
  }
  return { isMalicious: false };
}

// ================================================================
// 7. WAF MIDDLEWARE
// ================================================================
async function wafMiddleware(req, res, next) {
  const ip = getRealIP(req);
  
  if (req.path.startsWith('/_next/') || req.path.startsWith('/static/') || req.path === '/favicon.ico') {
    return next();
  }
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  try {
    const detection = detectMalicious(req);
    if (detection.isMalicious) {
      await redis.lpush('waf:attacks', JSON.stringify({
        ip, timestamp: new Date().toISOString(),
        path: req.path, method: req.method,
        pattern: detection.pattern
      }));
      await redis.ltrim('waf:attacks', 0, 1000);
      
      await redis.setex(`ban:${ip}`, 86400, JSON.stringify({
        bannedAt: new Date().toISOString(),
        reason: `WAF blocked: ${detection.pattern}`
      }));
      
      return res.status(403).json({
        error: 'WAF_BLOCKED',
        message: 'Request diblokir oleh WAF.',
        redirect: `/ban.html?ip=${encodeURIComponent(ip)}&reason=WAF blocked: ${detection.pattern}`
      });
    }
  } catch (error) {
    console.error('❌ WAF error:', error.message);
  }
  
  next();
}

app.use(wafMiddleware);

// ================================================================
// 8. LOG IP MIDDLEWARE
// ================================================================
async function logIP(req, res, next) {
  const ip = getRealIP(req);
  
  if (req.path.startsWith('/_next/') || req.path.startsWith('/static/') || req.path === '/favicon.ico') {
    return next();
  }
  
  try {
    const existing = await redis.get(`ip:${ip}`);
    let data = existing ? JSON.parse(existing) : { 
      firstSeen: new Date().toISOString(), 
      attempts: 0,
      totalVisits: 0
    };
    
    data.lastSeen = new Date().toISOString();
    data.totalVisits = (data.totalVisits || 0) + 1;
    data.userAgent = req.headers['user-agent'] || 'Unknown';
    data.path = req.path;
    
    await redis.setex(`ip:${ip}`, CONFIG.BAN_EXPIRY, JSON.stringify(data));
  } catch (error) {
    console.error('❌ Log IP error:', error.message);
  }
  
  next();
}

app.use(logIP);

// ================================================================
// 9. BAN CHECK MIDDLEWARE
// ================================================================
async function checkBan(req, res, next) {
  const ip = getRealIP(req);
  
  if (req.path === '/ban.html' || req.path.startsWith('/_next/') || req.path.startsWith('/static/')) {
    return next();
  }
  
  try {
    const redisBan = await redis.get(`ban:${ip}`);
    if (redisBan) {
      const banData = JSON.parse(redisBan);
      const redirectUrl = `/ban.html?ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent(banData.reason || 'Diblokir oleh admin')}&status=BANNED`;
      
      if (req.path.startsWith('/api/')) {
        return res.status(403).json({
          error: 'BANNED',
          message: 'IP Anda telah diblokir',
          redirect: redirectUrl
        });
      }
      
      return res.redirect(redirectUrl);
    }
  } catch (error) {
    console.error('❌ Check ban error:', error.message);
  }
  
  next();
}

app.use(checkBan);

// ================================================================
// 10. GENERATE SESSION SIGNATURE
// ================================================================
function generateSessionSignature(username, ip, userAgent, timestamp) {
  const raw = `${username}|${ip}|${userAgent}|${timestamp}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// ================================================================
// 11. SESSION MIDDLEWARE
// ================================================================
async function checkSession(req, res, next) {
  try {
    const sessionId = req.cookies?.sessionId;
    
    if (!sessionId) {
      return res.status(401).json({ error: 'NO_SESSION', message: 'Belum login.' });
    }
    
    const sessionData = await redis.get(`session:${sessionId}`);
    if (!sessionData) {
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'SESSION_EXPIRED', message: 'Session expired.' });
    }
    
    const session = JSON.parse(sessionData);
    const ip = getRealIP(req);
    const userAgent = req.headers['user-agent'] || '';
    
    if (session.ip && session.ip !== ip) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'IP_MISMATCH' });
    }
    
    if (session.userAgent && session.userAgent !== userAgent) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'DEVICE_MISMATCH' });
    }
    
    req.session = session;
    next();
  } catch (error) {
    console.error('❌ Session error:', error.message);
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Terjadi kesalahan.' });
  }
}

// ================================================================
// 12. DEVELOPER MIDDLEWARE
// ================================================================
async function checkDeveloper(req, res, next) {
  try {
    const sessionId = req.cookies?.sessionId;
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
    
    if (!session.isDeveloper || session.username !== developer.username) {
      return res.status(403).json({ error: 'FORBIDDEN', message: 'Hanya untuk developer.' });
    }
    
    req.session = session;
    next();
  } catch (error) {
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
}

// ================================================================
// 13. CAPTCHA
// ================================================================
app.get('/api/captcha', async (req, res) => {
  try {
    const captchaId = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const answer = num1 + num2;
    
    await redis.setex(`captcha:${captchaId}`, CONFIG.CAPTCHA_EXPIRY, answer.toString());
    
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
// 14. VERIFY CAPTCHA
// ================================================================
app.post('/api/verify', async (req, res) => {
  const ip = getRealIP(req);
  const userAgent = req.headers['user-agent'] || '';
  
  try {
    const { captchaId, answer, telegramUsername } = req.body;
    
    if (!captchaId || !answer || !telegramUsername) {
      return res.status(400).json({ error: 'Semua field wajib diisi!' });
    }
    
    const redisBan = await redis.get(`ban:${ip}`);
    if (redisBan) {
      const banData = JSON.parse(redisBan);
      return res.status(403).json({
        error: 'BANNED',
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
      const existing = await redis.get(`ip:${ip}`);
      let data = existing ? JSON.parse(existing) : { firstSeen: new Date().toISOString(), attempts: 0 };
      data.attempts = (data.attempts || 0) + 1;
      data.lastSeen = new Date().toISOString();
      
      await redis.setex(`ip:${ip}`, CONFIG.BAN_EXPIRY, JSON.stringify(data));
      
      if (data.attempts >= CONFIG.MAX_ATTEMPTS) {
        await redis.setex(`ban:${ip}`, CONFIG.BAN_EXPIRY, JSON.stringify({
          bannedAt: new Date().toISOString(),
          reason: 'Terlalu banyak percobaan login gagal (auto-ban)'
        }));
        return res.status(429).json({
          error: 'AUTO_BANNED',
          redirect: `/ban.html?ip=${encodeURIComponent(ip)}&reason=Auto-ban: too many attempts`
        });
      }
      
      return res.status(400).json({ error: 'Captcha salah! Coba lagi.' });
    }
    
    const existing = await redis.get(`ip:${ip}`);
    if (existing) {
      const data = JSON.parse(existing);
      data.attempts = 0;
      await redis.setex(`ip:${ip}`, CONFIG.BAN_EXPIRY, JSON.stringify(data));
    }
    
    const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
    const timestamp = Date.now();
    const developer = getDeveloperData();
    const isDeveloper = telegramUsername.toLowerCase() === developer.username.toLowerCase();
    const signature = generateSessionSignature(telegramUsername, ip, userAgent, timestamp);
    
    const sessionData = {
      username: telegramUsername,
      isDeveloper: isDeveloper,
      ip, userAgent, timestamp, signature,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + CONFIG.SESSION_EXPIRY * 1000).toISOString()
    };
    
    await redis.setex(`session:${sessionId}`, CONFIG.SESSION_EXPIRY, JSON.stringify(sessionData));
    
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: CONFIG.SESSION_EXPIRY * 1000
    });
    
    res.json({ success: true, isDeveloper: isDeveloper });
  } catch (error) {
    console.error('❌ Verify error:', error.message);
    res.status(500).json({ error: 'Terjadi kesalahan saat verifikasi.' });
  }
});

// ================================================================
// 15. DEVELOPER LOGIN
// ================================================================
app.post('/api/developer-login', async (req, res) => {
  const ip = getRealIP(req);
  const userAgent = req.headers['user-agent'] || '';
  
  try {
    const { username, password } = req.body;
    const developer = getDeveloperData();
    
    if (username === developer.username && password === developer.password) {
      const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
      const timestamp = Date.now();
      const signature = generateSessionSignature(username, ip, userAgent, timestamp);
      
      await redis.setex(`session:${sessionId}`, CONFIG.SESSION_EXPIRY, JSON.stringify({
        username, isDeveloper: true, isDeveloperLogin: true,
        ip, userAgent, timestamp, signature,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + CONFIG.SESSION_EXPIRY * 1000).toISOString()
      }));
      
      res.cookie('sessionId', sessionId, {
        httpOnly: true, secure: true, sameSite: 'strict',
        maxAge: CONFIG.SESSION_EXPIRY * 1000
      });
      
      res.json({ success: true, isDeveloper: true });
    } else {
      res.status(401).json({ error: 'Username atau password salah!' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Terjadi kesalahan.' });
  }
});

// ================================================================
// 16. CHECK SESSION
// ================================================================
app.get('/api/check-session', async (req, res) => {
  try {
    const sessionId = req.cookies?.sessionId;
    
    if (!sessionId) {
      return res.json({ valid: false, error: 'NO_SESSION' });
    }
    
    const sessionData = await redis.get(`session:${sessionId}`);
    if (!sessionData) {
      res.clearCookie('sessionId');
      return res.json({ valid: false, error: 'SESSION_EXPIRED' });
    }
    
    const session = JSON.parse(sessionData);
    const ip = getRealIP(req);
    const userAgent = req.headers['user-agent'] || '';
    
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
      isDeveloper: session.isDeveloper || false
    });
  } catch (error) {
    res.json({ valid: false, error: 'INTERNAL_ERROR' });
  }
});

// ================================================================
// 17. CHAT - SEND MESSAGE
// ================================================================
app.post('/api/chat/send', checkSession, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || message.length > CONFIG.MAX_MESSAGE_LENGTH) {
      return res.status(400).json({ error: `Pesan maksimal ${CONFIG.MAX_MESSAGE_LENGTH} karakter.` });
    }
    
    const isDeveloper = req.session.isDeveloper || false;
    const newMessage = {
      id: Date.now().toString(36) + Math.random().toString(36).substr(2, 4),
      username: req.session.username,
      message,
      isDeveloper,
      timestamp: new Date().toISOString()
    };
    
    await redis.rpush('chat:global', JSON.stringify(newMessage));
    await redis.expire('chat:global', 3600);
    
    res.json({ success: true, message: newMessage });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 18. CHAT - GET MESSAGES
// ================================================================
app.get('/api/chat/messages', checkSession, async (req, res) => {
  try {
    const messages = await redis.lrange('chat:global', 0, -1);
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
// 19. CHAT - CLEAR MESSAGES
// ================================================================
app.delete('/api/chat/clear', checkDeveloper, async (req, res) => {
  try {
    await redis.del('chat:global');
    res.json({ success: true, message: '✅ Semua pesan berhasil dihapus!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 20. TYPING INDICATOR
// ================================================================
app.post('/api/typing', checkSession, async (req, res) => {
  try {
    const { isTyping } = req.body;
    const username = req.session.username;
    
    if (isTyping) {
      await redis.sadd('typing:users', username);
      await redis.expire('typing:users', 5);
    } else {
      await redis.srem('typing:users', username);
    }
    
    const typingUsers = await redis.smembers('typing:users');
    res.json({ success: true, typingUsers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/typing-users', checkSession, async (req, res) => {
  try {
    const typingUsers = await redis.smembers('typing:users');
    res.json({ success: true, typingUsers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 21. ONLINE USERS
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
// 22. IP LIST
// ================================================================
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
          ip,
          firstSeen: info.firstSeen,
          lastSeen: info.lastSeen,
          attempts: info.attempts || 0,
          totalVisits: info.totalVisits || 0,
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

// ================================================================
// 23. BAN IP
// ================================================================
app.post('/api/ban-ip', checkDeveloper, async (req, res) => {
  try {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP wajib diisi!' });
    
    await redis.setex(`ban:${ip}`, CONFIG.BAN_EXPIRY, JSON.stringify({
      bannedAt: new Date().toISOString(),
      reason: reason || 'Diblokir oleh admin'
    }));
    
    res.json({
      success: true,
      message: `✅ IP ${ip} berhasil diblokir.`,
      redirect: `/ban.html?ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent(reason || 'Diblokir oleh admin')}`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 24. UNBAN IP
// ================================================================
app.post('/api/unban-ip', checkDeveloper, async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP wajib diisi!' });
    
    await redis.del(`ban:${ip}`);
    res.json({ success: true, message: `✅ IP ${ip} berhasil di-unblokir.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 25. DELETE IP
// ================================================================
app.delete('/api/delete-ip', checkDeveloper, async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP wajib diisi!' });
    
    const isBanned = await redis.get(`ban:${ip}`);
    if (isBanned) {
      return res.status(400).json({
        error: 'IP ini masih diban. Unban dulu sebelum menghapus.',
        isBanned: true
      });
    }
    
    await redis.del(`ip:${ip}`);
    res.json({ success: true, message: `✅ IP ${ip} berhasil dihapus.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 26. WAF STATS
// ================================================================
app.get('/api/waf-stats', checkDeveloper, async (req, res) => {
  try {
    const statsKey = 'waf:stats';
    const stats = await redis.get(statsKey);
    let wafStats = stats ? JSON.parse(stats) : {
      totalRequests: 0, uniqueIPs: 0, bannedIPs: 0,
      totalAttacks: 0, lastUpdated: new Date().toISOString(), history: []
    };
    
    const allIPs = await redis.keys('ip:*');
    const bannedKeys = await redis.keys('ban:*');
    const attacks = await redis.lrange('waf:attacks', 0, -1);
    
    wafStats.uniqueIPs = allIPs.length;
    wafStats.bannedIPs = bannedKeys.length;
    wafStats.totalAttacks = attacks.length;
    wafStats.lastUpdated = new Date().toISOString();
    
    const recentAttacks = await redis.lrange('waf:attacks', 0, 9);
    wafStats.recentAttacks = recentAttacks.map(a => JSON.parse(a));
    
    res.json({ success: true, stats: wafStats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 27. TEST SECURITY
// ================================================================
app.get('/api/test-security', checkDeveloper, async (req, res) => {
  try {
    const keys = await redis.keys('ip:*');
    const banKeys = await redis.keys('ban:*');
    const attacks = await redis.lrange('waf:attacks', 0, -1);
    
    res.json({
      success: true,
      message: '✅ Security Gateway berfungsi normal!',
      session: req.session,
      totalIPs: keys.length,
      totalBanned: banKeys.length,
      totalAttacks: attacks.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 28. LOGOUT
// ================================================================
app.post('/api/logout', async (req, res) => {
  try {
    const sessionId = req.cookies?.sessionId;
    if (sessionId) await redis.del(`session:${sessionId}`);
    res.clearCookie('sessionId');
    res.json({ success: true, message: 'Logout berhasil.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================================
// 29. PING
// ================================================================
app.get('/api/ping', async (req, res) => {
  try {
    const pong = await redis.ping();
    res.json({ status: '✅ Redis Connected!', pong });
  } catch (error) {
    res.status(500).json({ status: '❌ Redis Error', error: error.message });
  }
});

// ================================================================
// 30. 404 & ERROR HANDLER
// ================================================================
app.use((req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', message: 'Endpoint tidak ditemukan.' });
});

app.use((err, req, res, next) => {
  console.error('❌ Global error:', err.message);
  res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Terjadi kesalahan server.' });
});

module.exports = app;
