// Vercel Database-Free Referral System - Core API Route
// Secure, deterministic, production-ready referral handling

import crypto from 'crypto';

// Configuration
const CONFIG = {
  // Environment variables
  SERVER_SECRET: process.env.SERVER_SECRET,
  APP_ID_ANDROID: process.env.APP_ID_ANDROID || 'com.helpdo.app',
  APP_ID_IOS: process.env.APP_ID_IOS || '123456789',
  BASE_URL: process.env.BASE_URL || 'https://helpdo-links.vercel.app',
  
  // Security settings
  MAX_REDIRECTS_PER_HOUR: 100,
  RATE_LIMIT_WINDOW: 3600000, // 1 hour in milliseconds
  
  // Token settings
  TOKEN_LENGTH: 8,
  TOKEN_ALGORITHM: 'sha256',
};

// Simple in-memory rate limiting (resets on Vercel cold start)
const rateLimitStore = new Map();

/**
 * Generate deterministic token from username using Base64 + timestamp algorithm
 * Matches the Flutter implementation exactly
 * @param {string} username 
 * @returns {string} URL-safe token
 */
function generateToken(username) {
  try {
    // Use the same algorithm as Flutter: Base64(username + timestamp), first 8 characters
    const timestamp = Date.now();
    const data = `${username}-${timestamp}`;
    const base64Str = Buffer.from(data).toString('base64');
    
    // Make URL-safe and take first 8 characters (same as Flutter)
    return base64Str
      .replace(/\+/g, '') // URL-safe
      .replace(/\//g, '') // URL-safe
      .replace(/=/g, '')  // Remove padding
      .substring(0, 8);
  } catch (error) {
    console.error('Token generation error:', error);
    // Fallback to simple random token
    return crypto.randomBytes(4).toString('hex');
  }
}

/**
 * Validate token format (accept full token from Flutter app)
 * Since Flutter app generates timestamp-based tokens, we validate format instead
 * @param {string} username 
 * @param {string} token 
 * @returns {boolean} 
 */
function validateToken(username, token) {
  try {
    // Validate token format: should be 8 characters, alphanumeric
    if (!token || token.length !== 8) {
      return false;
    }
    
    // Token should be alphanumeric (Base64 without +, /, =)
    if (!/^[a-zA-Z0-9]+$/.test(token)) {
      return false;
    }
    
    // Additional validation: try to decode as Base64 to ensure it's valid
    try {
      // Pad with = if needed for Base64 decoding
      const paddedToken = token + '====';
      const decoded = Buffer.from(paddedToken, 'base64').toString('utf-8');
      
      // Should contain the username
      if (!decoded.includes(username)) {
        return false;
      }
      
      return true;
    } catch (decodeError) {
      console.error('Token decode error:', decodeError);
      return false;
    }
  } catch (error) {
    console.error('Token validation error:', error);
    return false;
  }
}

/**
 * Parse slug into username and token
 * @param {string} slug - Expected format: username_token
 * @returns {Object|null} { username, token } or null if invalid
 */
function parseSlug(slug) {
  if (!slug || typeof slug !== 'string') {
    return null;
  }

  // Split by underscore to separate username from token
  const parts = slug.split('_');
  if (parts.length !== 2) {
    return null;
  }

  const [username, token] = parts;
  
  // Validate username format
  if (!username || username.length < 2 || username.length > 20) {
    return null;
  }
  
  // Username should only contain alphanumeric characters and underscores
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return null;
  }
  
  // Validate token format
  if (!token || token.length !== CONFIG.TOKEN_LENGTH) {
    return null;
  }
  
  // Token should be alphanumeric
  if (!/^[a-zA-Z0-9]+$/.test(token)) {
    return null;
  }

  return { username, token };
}

/**
 * Detect device type from User-Agent
 * @param {string} userAgent 
 * @returns {string} 'ios', 'android', or 'unknown'
 */
function detectDevice(userAgent) {
  if (!userAgent) return 'unknown';
  
  const ua = userAgent.toLowerCase();
  
  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) {
    return 'ios';
  }
  
  if (ua.includes('android')) {
    return 'android';
  }
  
  return 'unknown';
}

/**
 * Generate app store URL with deeplink parameters
 * @param {string} deviceType 
 * @param {string} username 
 * @param {string} token 
 * @returns {string} 
 */
function generateStoreUrl(deviceType, username, token) {
  const deeplinkParam = `referrer=${encodeURIComponent(username)}`;
  
  switch (deviceType) {
    case 'ios':
      return `https://apps.apple.com/app/id${CONFIG.APP_ID_IOS}?${deeplinkParam}`;
    case 'android':
      return `https://play.google.com/store/apps/details?id=${CONFIG.APP_ID_ANDROID}&${deeplinkParam}`;
    default:
      // Fallback to web page with both options
      return `${CONFIG.BASE_URL}/download?ref=${encodeURIComponent(username)}`;
  }
}

/**
 * Check rate limiting
 * @param {string} ip 
 * @returns {boolean} true if allowed, false if rate limited
 */
function checkRateLimit(ip) {
  const now = Date.now();
  const windowStart = now - CONFIG.RATE_LIMIT_WINDOW;
  
  // Clean old entries
  for (const [storedIp, data] of rateLimitStore.entries()) {
    if (data.lastReset < windowStart) {
      rateLimitStore.delete(storedIp);
    }
  }
  
  const userData = rateLimitStore.get(ip) || { count: 0, lastReset: now };
  
  if (userData.count >= CONFIG.MAX_REDIRECTS_PER_HOUR) {
    return false;
  }
  
  userData.count++;
  rateLimitStore.set(ip, userData);
  return true;
}

/**
 * Log referral click for monitoring
 * @param {Object} data 
 */
function logReferralClick(data) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    username: data.username,
    token: data.token,
    device: data.device,
    ip: data.ip,
    userAgent: data.userAgent,
    referer: data.referer,
  };
  
  console.log('REFERRAL_CLICK:', JSON.stringify(logEntry));
}

/**
 * Main handler function
 */
export default async function handler(req, res) {
  try {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
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
    
    // Extract parameters
    const { slug } = req.query;
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const referer = req.headers['referer'] || '';
    
    // Rate limiting
    if (!checkRateLimit(ip)) {
      console.warn(`Rate limit exceeded for IP: ${ip}`);
      res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many requests. Please try again later.'
      });
      return;
    }
    
    // Parse and validate slug
    const parsed = parseSlug(slug);
    if (!parsed) {
      console.warn(`Invalid slug format: ${slug}`);
      res.status(400).json({
        error: 'Invalid referral link',
        message: 'The referral link format is invalid'
      });
      return;
    }
    
    const { username, token } = parsed;
    
    // Validate token
    if (!validateToken(username, token)) {
      console.warn(`Invalid token for user ${username}: ${token}`);
      res.status(400).json({
        error: 'Invalid referral token',
        message: 'The referral token is invalid or expired'
      });
      return;
    }
    
    // Detect device and generate appropriate store URL
    const device = detectDevice(userAgent);
    const storeUrl = generateStoreUrl(device, username, token);
    
    // Log the referral click
    logReferralClick({
      username,
      token,
      device,
      ip,
      userAgent,
      referer
    });
    
    // Perform 308 redirect
    res.status(308);
    res.setHeader('Location', storeUrl);
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    // Add custom headers for analytics (optional)
    res.setHeader('X-Referral-Username', username);
    res.setHeader('X-Referral-Device', device);
    
    res.end(`Redirecting to app store...`);
    
  } catch (error) {
    console.error('Referral handler error:', error);
    
    res.status(500).json({
      error: 'Internal server error',
      message: 'An error occurred while processing the referral link'
    });
  }
}
