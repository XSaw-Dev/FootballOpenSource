// ===== REDIS CONNECTION =====
const Redis = require('ioredis');

const redis = new Redis({
  host: 'cosmic-moose-166150.upstash.io',
  port: 6379,
  password: 'gQAAAAAAAokGAAIgcDJmZTA5NTM5OTJkNzQ0NjJiOTIxNzUyMzZlMTg4ZGNlMA',
  tls: {},
  retryStrategy: (times) => Math.min(times * 50, 2000)
});

redis.on('error', (err) => console.error('❌ Redis Error:', err));
redis.on('connect', () => console.log('✅ Redis Connected!'));

module.exports = redis;
