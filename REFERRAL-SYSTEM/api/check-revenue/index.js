// Revenue Check API - Hybrid Version
// Simple logic with production-ready security and features

// Configuration
import crypto from 'crypto';

// Configuration
const CONFIG = {
  // Test data for development/testing
  REVENUE_DATA: {
    'max': 25,
    'test': 30,
    'demo': 40
  },
  
  // Security and performance settings
  ELIGIBILITY_THRESHOLD: 20,
  CACHE_TTL: 300000, // 5 minutes
  MAX_REQUESTS_PER_MINUTE: 60,
  
  // Security headers
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(',') || ['*']
};

// Simple in-memory cache and rate limiting
const cache = new Map();
const rateLimitStore = new Map();

/**
 * Check rate limiting
 */
function checkRateLimit(ip) {
  const now = Date.now();
  const userData = rateLimitStore.get(ip) || { count: 0, windowStart: now };
  
  // Reset window if needed
  if (now - userData.windowStart > 60000) { // 1 minute
    userData.count = 0;
    userData.windowStart = now;
  }
  
  if (userData.count >= CONFIG.MAX_REQUESTS_PER_MINUTE) {
    return false;
  }
  
  userData.count++;
  rateLimitStore.set(ip, userData);
  return true;
}

/**
 * Cache management
 */
function getCachedResult(key) {
  const cached = cache.get(key);
  if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_TTL) {
    return cached.data;
  }
  return null;
}

function setCachedResult(key, data) {
  cache.set(key, {
    data,
    timestamp: Date.now()
  });
}

/**
 * Log revenue checks for monitoring
 */
function logRevenueCheck(data) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    userId: data.userId,
    revenue: data.revenue,
    eligible: data.eligible,
    ip: data.ip,
    source: 'hybrid_revenue_api'
  };
  console.log('REVENUE_CHECK:', JSON.stringify(logEntry));
}

/**
 * Main handler function - HYBRID VERSION
 */
export default async function handler(req, res) {
  try {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.status(200).end();
      return;
    }
    
    // Only allow GET requests
    if (req.method !== 'GET') {
      res.status(405).json({
        error: 'Method not allowed',
        message: 'Only GET requests are supported'
      });
      return;
    }
    
    // Rate limiting
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(ip)) {
      res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many requests. Please try again later.'
      });
      return;
    }
    
    // AKZEPTIERE BEIDES: 'user' UND 'userId' (as requested)
    const userId = req.query.user || req.query.userId || 'unknown';
    
    // Check cache first
    const cacheKey = `revenue_${userId}`;
    let result = getCachedResult(cacheKey);
    
    if (!result) {
      // Simple logic as requested: hardcoded test data
      const revenue = CONFIG.REVENUE_DATA[userId] || 0;
      const eligible = revenue >= CONFIG.ELIGIBILITY_THRESHOLD;
      
      result = {
        user: userId,
        revenue,
        eligible,
        threshold: CONFIG.ELIGIBILITY_THRESHOLD,
        timestamp: new Date().toISOString(),
        cached: false
      };
      
      // Cache the result
      setCachedResult(cacheKey, result);
    } else {
      result.cached = true;
    }
    
    // Log the check
    logRevenueCheck({
      userId,
      revenue: result.revenue,
      eligible: result.eligible,
      ip
    });
    
    // Return response
    res.status(200).json(result);
    
  } catch (error) {
    console.error('Revenue check error:', error);
    
    res.status(500).json({
      error: 'Internal server error',
      message: 'An error occurred while checking revenue eligibility',
      timestamp: new Date().toISOString()
    });
  }
}
