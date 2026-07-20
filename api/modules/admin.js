// ===== ADMIN MODULE =====
const redis = require('./redis');
const { BAN_EXPIRY } = require('./config');

// ===== IP LIST =====
async function getIPList(req, res) {
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
}

// ===== BAN IP =====
async function banIP(req, res) {
  try {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP wajib diisi!' });
    
    await redis.setex(`ban:${ip}`, BAN_EXPIRY, JSON.stringify({
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
}

// ===== UNBAN IP =====
async function unbanIP(req, res) {
  try {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP wajib diisi!' });
    
    await redis.del(`ban:${ip}`);
    res.json({ success: true, message: `✅ IP ${ip} berhasil di-unblokir.` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

// ===== DELETE IP HISTORY =====
async function deleteIP(req, res) {
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
}

// ===== WAF STATS =====
async function getWAFStats(req, res) {
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
}

// ===== TEST SECURITY =====
async function testSecurity(req, res) {
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
}

module.exports = {
  getIPList,
  banIP,
  unbanIP,
  deleteIP,
  getWAFStats,
  testSecurity
};
