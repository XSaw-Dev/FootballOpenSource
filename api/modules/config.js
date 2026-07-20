// ===== CONFIG & CONSTANTS =====
module.exports = {
  SESSION_EXPIRY: 7 * 24 * 3600, // 7 hari
  CAPTCHA_EXPIRY: 300, // 5 menit
  MAX_MESSAGE_LENGTH: 500,
  MAX_ATTEMPTS: 5,
  BAN_EXPIRY: 2592000, // 30 hari
  WAF_HISTORY_LIMIT: 50,
  ATTACK_LOG_LIMIT: 1000,
  
  // Rate limits
  RATE_LIMITS: {
    general: { window: 15 * 60 * 1000, max: 100 },
    login: { window: 15 * 60 * 1000, max: 20 },
    chat: { window: 60 * 1000, max: 30 },
  }
};
