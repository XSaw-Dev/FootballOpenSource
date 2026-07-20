// ================================================================
// AUTH MODULE - api/modules/auth.js
// ================================================================
const redis = require('./redis');
const { SESSION_EXPIRY, CAPTCHA_EXPIRY, MAX_ATTEMPTS, BAN_EXPIRY } = require('./config');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ===== GET REAL IP =====
function getRealIP(req) {
  try {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           req.headers['cf-connecting-ip'] ||
           req.headers['true-client-ip'] ||
           req.ip ||
           req.connection?.remoteAddress ||
           '0.0.0.0';
  } catch {
    return '0.0.0.0';
  }
}

// ===== LOAD DEVELOPER DATA =====
function getDeveloperData() {
  try {
    const filePath = path.join(__dirname, '../developer.json');
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('❌ Gagal baca developer.json:', error.message);
    return { username: 'I7ZX', password: 'GueYangBikin' };
  }
}

// ===== GENERATE SESSION SIGNATURE =====
function generateSessionSignature(username, ip, userAgent, timestamp) {
  const raw = `${username}|${ip}|${userAgent}|${timestamp}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// ================================================================
// SESSION MIDDLEWARE (FIXED - PAKE TRY-CATCH)
// ================================================================
async function checkSession(req, res, next) {
  try {
    const sessionId = req.cookies?.sessionId;
    
    if (!sessionId) {
      return res.status(401).json({ 
        error: 'NO_SESSION', 
        message: 'Belum login atau session tidak ditemukan.' 
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
    
    const session = JSON.parse(sessionData);
    const ip = getRealIP(req);
    const userAgent = req.headers['user-agent'] || '';
    
    // Validasi IP
    if (session.ip && session.ip !== ip) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'IP_MISMATCH', message: 'IP berbeda dengan session.' });
    }
    
    // Validasi User-Agent
    if (session.userAgent && session.userAgent !== userAgent) {
      await redis.del(`session:${sessionId}`);
      res.clearCookie('sessionId');
      return res.status(401).json({ error: 'DEVICE_MISMATCH', message: 'Device berbeda.' });
    }
    
    // Refresh session (perpanjang)
    await redis.expire(`session:${sessionId}`, SESSION_EXPIRY);
    
    req.session = session;
    next();
  } catch (error) {
    console.error('❌ Check session error:', error.message);
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Terjadi kesalahan saat verifikasi session.' });
  }
}

// ================================================================
// DEVELOPER MIDDLEWARE
// ================================================================
async function checkDeveloper(req, res, next) {
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
    const developer = getDeveloperData();
    
    if (!session.isDeveloper || session.username !== developer.username) {
      return res.status(403).json({ error: 'FORBIDDEN', message: 'Akses ditolak. Hanya untuk developer.' });
    }
    
    // Refresh session
    await redis.expire(`session:${sessionId}`, SESSION_EXPIRY);
    
    req.session = session;
    next();
  } catch (error) {
    console.error('❌ Check developer error:', error.message);
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Terjadi kesalahan.' });
  }
}

// ================================================================
// CAPTCHA
// ================================================================
async function generateCaptcha(req, res) {
  try {
    const captchaId = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const answer = num1 + num2;
    
    await redis.setex(`captcha:${captchaId}`, CAPTCHA_EXPIRY, answer.toString());
    
    res.json({
      success: true,
      captchaId,
      question: `${num1} + ${num2} = ?`
    });
  } catch (error) {
    console.error('❌ Generate captcha error:', error.message);
    res.json({
      success: true,
      captchaId: 'fallback-' + Date.now(),
      question: '3 + 4 = ?'
    });
  }
}

// ================================================================
// VERIFY CAPTCHA
// ================================================================
async function verifyCaptcha(req, res) {
  const ip = getRealIP(req);
  const userAgent = req.headers['user-agent'] || '';
  
  try {
    const { captchaId, answer, telegramUsername } = req.body;
    
    if (!captchaId || !answer || !telegramUsername) {
      return res.status(400).json({ error: 'Semua field wajib diisi!' });
    }
    
    // Cek ban
    const redisBan = await redis.get(`ban:${ip}`);
    if (redisBan) {
      const banData = JSON.parse(redisBan);
      return res.status(403).json({ 
        error: 'BANNED',
        message: 'IP Anda telah diblokir.',
        redirect: `/ban.html?ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent(banData.reason || 'Diblokir oleh admin')}`
      });
    }
    
    // Verifikasi captcha
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
      const existing = await redis.get(`ip:${ip}`);
      let data = existing ? JSON.parse(existing) : { firstSeen: new Date().toISOString(), attempts: 0 };
      data.attempts = (data.attempts || 0) + 1;
      data.lastSeen = new Date().toISOString();
      
      await redis.setex(`ip:${ip}`, BAN_EXPIRY, JSON.stringify(data));
      
      // Auto-ban kalo 5 attempts
      if (data.attempts >= MAX_ATTEMPTS) {
        await redis.setex(`ban:${ip}`, BAN_EXPIRY, JSON.stringify({
          bannedAt: new Date().toISOString(),
          reason: 'Terlalu banyak percobaan login gagal (auto-ban)'
        }));
        return res.status(429).json({ 
          error: 'AUTO_BANNED',
          message: 'IP Anda diblokir otomatis.',
          redirect: `/ban.html?ip=${encodeURIComponent(ip)}&reason=Auto-ban: too many attempts`
        });
      }
      
      return res.status(400).json({ error: 'Captcha salah! Coba lagi.' });
    }
    
    // Reset attempts
    const existing = await redis.get(`ip:${ip}`);
    if (existing) {
      const data = JSON.parse(existing);
      data.attempts = 0;
      await redis.setex(`ip:${ip}`, BAN_EXPIRY, JSON.stringify(data));
    }
    
    // Buat session
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
      expiresAt: new Date(Date.now() + SESSION_EXPIRY * 1000).toISOString()
    };
    
    await redis.setex(`session:${sessionId}`, SESSION_EXPIRY, JSON.stringify(sessionData));
    
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: SESSION_EXPIRY * 1000
    });
    
    res.json({ 
      success: true, 
      message: '✅ Verifikasi berhasil!',
      isDeveloper: isDeveloper
    });
  } catch (error) {
    console.error('❌ Verify captcha error:', error.message);
    res.status(500).json({ error: 'Terjadi kesalahan saat verifikasi.' });
  }
}

// ================================================================
// DEVELOPER LOGIN
// ================================================================
async function developerLogin(req, res) {
  const ip = getRealIP(req);
  const userAgent = req.headers['user-agent'] || '';
  
  try {
    const { username, password } = req.body;
    const developer = getDeveloperData();
    
    if (username === developer.username && password === developer.password) {
      const sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 10);
      const timestamp = Date.now();
      const signature = generateSessionSignature(username, ip, userAgent, timestamp);
      
      await redis.setex(`session:${sessionId}`, SESSION_EXPIRY, JSON.stringify({
        username, isDeveloper: true, isDeveloperLogin: true,
        ip, userAgent, timestamp, signature,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + SESSION_EXPIRY * 1000).toISOString()
      }));
      
      res.cookie('sessionId', sessionId, {
        httpOnly: true, secure: true, sameSite: 'strict',
        maxAge: SESSION_EXPIRY * 1000
      });
      
      res.json({ success: true, isDeveloper: true });
    } else {
      res.status(401).json({ error: 'Username atau password salah!' });
    }
  } catch (error) {
    console.error('❌ Developer login error:', error.message);
    res.status(500).json({ error: 'Terjadi kesalahan.' });
  }
}

// ================================================================
// CHECK SESSION API (FIXED - PAKE TRY-CATCH)
// ================================================================
async function checkSessionAPI(req, res) {
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
    
    // Refresh session
    await redis.expire(`session:${sessionId}`, SESSION_EXPIRY);
    
    res.json({ 
      valid: true, 
      username: session.username,
      isDeveloper: session.isDeveloper || false,
      expiresAt: session.expiresAt
    });
  } catch (error) {
    console.error('❌ Check session API error:', error.message);
    res.json({ valid: false, error: 'INTERNAL_ERROR' });
  }
}

// ================================================================
// LOGOUT
// ================================================================
async function logout(req, res) {
  try {
    const sessionId = req.cookies?.sessionId;
    if (sessionId) {
      await redis.del(`session:${sessionId}`);
    }
    res.clearCookie('sessionId');
    res.json({ success: true, message: 'Logout berhasil.' });
  } catch (error) {
    console.error('❌ Logout error:', error.message);
    res.status(500).json({ error: 'Terjadi kesalahan.' });
  }
}

module.exports = {
  getRealIP,
  getDeveloperData,
  generateSessionSignature,
  checkSession,
  checkDeveloper,
  generateCaptcha,
  verifyCaptcha,
  developerLogin,
  checkSessionAPI,
  logout
};
