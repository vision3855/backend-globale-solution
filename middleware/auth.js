import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { securityLog, auditLog } from '../utils/logger.js';
import dotenv from 'dotenv';
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRE = process.env.JWT_EXPIRE || '15m';
const JWT_REFRESH_EXPIRE = process.env.JWT_REFRESH_EXPIRE || '7d';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters long');
}

// Token blacklist for logout (in production, use Redis)
const tokenBlacklist = new Set();

export const generateToken = (userId) => {
  return jwt.sign(
    { userId, type: 'access' }, 
    JWT_SECRET, 
    { 
      expiresIn: JWT_EXPIRE,
      issuer: 'inventory-api',
      audience: 'inventory-client'
    }
  );
};

export const generateRefreshToken = (userId) => {
  return jwt.sign(
    { userId, type: 'refresh' },
    JWT_SECRET,
    {
      expiresIn: JWT_REFRESH_EXPIRE,
      issuer: 'inventory-api',
      audience: 'inventory-client'
    }
  );
};

export const verifyToken = (token) => {
  try {
    if (tokenBlacklist.has(token)) {
      throw new Error('Token revoked');
    }
    return jwt.verify(token, JWT_SECRET, {
      issuer: 'inventory-api',
      audience: 'inventory-client',
      algorithms: ['HS256'] // Explicitly allow only HS256
    });
  } catch (error) {
    throw error;
  }
};

export const revokeToken = (token) => {
  tokenBlacklist.add(token);
  // Clean up old tokens periodically (in production, use Redis TTL)
  if (tokenBlacklist.size > 10000) {
    tokenBlacklist.clear();
  }
};

export const protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      securityLog('AUTH_MISSING_TOKEN', {
        ip: req.ip,
        path: req.path,
        userAgent: req.headers['user-agent']
      });
      return res.status(401).json({ success: false, error: 'Not authorized, no token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = verifyToken(token);
    } catch (jwtError) {
      securityLog('AUTH_INVALID_TOKEN', {
        ip: req.ip,
        error: jwtError.message,
        path: req.path
      });
      return res.status(401).json({ success: false, error: 'Not authorized, invalid or expired token' });
    }

    // Check token type
    if (decoded.type !== 'access') {
      return res.status(401).json({ success: false, error: 'Invalid token type' });
    }

    // Fetch user
    const user = await User.findById(decoded.userId).select('+passwordChangedAt');
    
    if (!user) {
      securityLog('AUTH_USER_NOT_FOUND', {
        userId: decoded.userId,
        ip: req.ip
      });
      return res.status(401).json({ success: false, error: 'User no longer exists' });
    }

    if (!user.isActive) {
      securityLog('AUTH_INACTIVE_USER', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });
      return res.status(401).json({ success: false, error: 'Account has been deactivated' });
    }

    // Check if password was changed after token was issued
    if (user.passwordChangedAt && decoded.iat * 1000 < user.passwordChangedAt.getTime()) {
      securityLog('AUTH_TOKEN_AFTER_PASSWORD_CHANGE', {
        userId: user._id,
        ip: req.ip
      });
      return res.status(401).json({ success: false, error: 'Password recently changed, please log in again' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    securityLog('AUTH_MIDDLEWARE_ERROR', {
      error: error.message,
      ip: req.ip
    });
    res.status(401).json({ success: false, error: 'Not authorized' });
  }
};

// Role-based access control
export const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      auditLog('UNAUTHORIZED_ACCESS_ATTEMPT', req.user, {
        ip: req.ip,
        requiredRoles: roles,
        attemptedPath: req.path,
        method: req.method
      });
      return res.status(403).json({ 
        success: false, 
        error: `Access denied. Required role: ${roles.join(' or ')}` 
      });
    }
    next();
  };
};

// Read-only for staff, modifications require admin/manager
export const readOnlyForStaff = (req, res, next) => {
  if (req.method === 'GET') {
    return next();
  }
  if (!['admin', 'manager'].includes(req.user.role)) {
    auditLog('MODIFICATION_ATTEMPT_BY_STAFF', req.user, {
      ip: req.ip,
      method: req.method,
      path: req.path
    });
    return res.status(403).json({ 
      success: false, 
      error: 'Access denied. Only admin or manager can modify data.' 
    });
  }
  next();
};

// Logout handler
export const logout = (req, res) => {
  if (req.token) {
    revokeToken(req.token);
  }
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  auditLog('USER_LOGOUT', req.user, {
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
  res.json({ success: true, message: 'Logged out successfully' });
};