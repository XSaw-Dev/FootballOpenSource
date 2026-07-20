// ===== ADVANCED WAF =====
const redis = require('./redis');
const { RATE_LIMITS, ATTACK_LOG_LIMIT } = require('./config');
const rateLimit = require('express-rate-limit');

// ===== MALICIOUS PATTERNS =====
const patterns = [
  // SQL Injection
  /(\bSELECT\b.*\bFROM\b|\bINSERT\b.*\bINTO\b|\bUPDATE\b.*\bSET\b|\bDELETE\b.*\bFROM\b|\bDROP\b.*\bTABLE\b|\bUNION\b.*\bSELECT\b)/i,
  /('.*\bOR\b.*'='.*'|'.*\bAND\b.*'='.*')/i,
  /(\bEXEC\b.*\bXP_|;\s*SHUTDOWN\b)/i,
  /('|\b1\b\s*=\s*\b1\b|'|\b1\b\s*=\s*\b'1\b)/i,
  /(--\s*.*\b\w+\b|#\s*.*\b\w+\b)/i,
  
  // XSS
  /<script\b[^>]*>.*?<\/script>/i,
  /<img\b[^>]*\bonerror\s*=/i,
  /<iframe\b[^>]*\bsrc\s*=/i,
  /javascript\s*:/i,
  /on\w+\s*=\s*['"]?[^'">]*\(/i,
  
  // Path Traversal
  /\.\.\/|\.\.\\/,
  /\/etc\/passwd|\/etc\/shadow/i,
  
  // Command Injection
  /;\s*rm\s+-rf\s+\//i,
  /;\s*curl\s+.*\s*\|.*\s*sh/i,
  /;\s*wget\s+.*\s*-O\s*/i,
  
  // Bot Detection
  /bot|crawler|spider|scraper|curl|wget|python|java|php|ruby|perl|go|nmap|sqlmap|nikto|openvas|metasploit/i,
];

// ===== DETECT FUNCTION =====
function detectMaliciousRequest(req) {
  const body = JSON.stringify(req.body || {});
  const query = JSON.stringify(req.query || {});
  const params = JSON.stringify(req.params || {});
  const headers = JSON.stringify(req.headers || {});
  const userAgent = req.headers['user-agent'] || '';
  
  const allData = `${body} ${query} ${params} ${headers} ${userAgent}`;
  
  for (const pattern of patterns) {
    if (pattern.test(allData)) {
      return { isMalicious: true, pattern: pattern.source };
    }
  }
  
  if (Buffer.byteLength(JSON.stringify(req.body), 'utf8') > 100000) {
    return { isMalicious: true, pattern: 'PAYLOAD_SIZE_EXCEEDED' };
  }
  
  if (/bot|crawler|spider|scraper|curl|wget|python|java|php|ruby|perl|go/i.test(userAgent)) {
    return { isMalicious: true, pattern: 'BOT_DETECTED' };
  }
  
  return { isMalicious: false };
}

// ===== WAF MIDDLEWARE =====
async function wafMiddleware(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
  
  if (req.path.startsWith('/_next/') || req.path.startsWith('/static/') || req.path === '/favicon.ico') {
    return next();
  }
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  try {
    const detection = detectMaliciousRequest(req);
    if (detection.isMalicious) {
      await redis.lpush('waf:attacks', JSON.stringify({
        ip, timestamp: new Date().toISOString(),
        path: req.path, method: req.method,
        pattern: detection.pattern
      }));
      await redis.ltrim('waf:attacks', 0, ATTACK_LOG_LIMIT);
      
      await redis.setex(`ban:${ip}`, 86400, JSON.stringify({
        bannedAt: new Date().toISOString(),
        reason: `WAF blocked: ${detection.pattern}`
      }));
      
      console.log(`🛡️ WAF blocked ${ip}: ${detection.pattern}`);
      
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

// ===== RATE LIMITERS =====
const generalLimiter = rateLimit({
  windowMs: RATE_LIMITS.general.window,
  max: RATE_LIMITS.general.max,
  message: { error: '⛔ Terlalu banyak request. Coba lagi nanti.' }
});

const loginLimiter = rateLimit({
  windowMs: RATE_LIMITS.login.window,
  max: RATE_LIMITS.login.max,
  message: { error: '⛔ Terlalu banyak percobaan login.' }
});

const chatLimiter = rateLimit({
  windowMs: RATE_LIMITS.chat.window,
  max: RATE_LIMITS.chat.max,
  message: { error: '⛔ Terlalu banyak pesan.' }
});

module.exports = {
  wafMiddleware,
  generalLimiter,
  loginLimiter,
  chatLimiter,
  detectMaliciousRequest
};
