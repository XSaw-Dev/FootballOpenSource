// ================================================================
// REDIS CONNECTION - api/modules/redis.js
// ================================================================
const Redis = require('ioredis');

console.log('🔄 Menghubungkan ke Redis...');

const redis = new Redis({
  host: 'cosmic-moose-166150.upstash.io',
  port: 6379,
  password: 'gQAAAAAAAokGAAIgcDJmZTA5NTM5OTJkNzQ0NjJiOTIxNzUyMzZlMTg4ZGNlMA',
  tls: {},
  retryStrategy: (times) => {
    if (times > 10) {
      console.error('❌ Redis: gagal konek setelah 10 percobaan.');
      return null; // stop retry
    }
    return Math.min(times * 50, 2000);
  }
});

redis.on('error', (err) => {
  console.error('❌ Redis Error:', err.message);
});

redis.on('connect', () => {
  console.log('✅ Redis Connected!');
});

redis.on('ready', () => {
  console.log('✅ Redis Ready!');
});

module.exports = redis;
