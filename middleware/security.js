import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import helmet from 'helmet';
import xss from 'xss-clean';
import { v4 as uuidv4 } from 'uuid';
import logger, { securityLog } from '../utils/logger.js';

// Request ID for tracing
export const requestId = (req, res, next) => {
  req.id = uuidv4();
  res.setHeader('X-Request-Id', req.id);
  next();
};

// Security headers with Helmet
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Required for Tailwind
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", process.env.CORS_ORIGIN || 'http://localhost:3000'],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false, // Allow for development
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true,
});

// CORS configuration
export const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like Postman or mobile apps)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200, // Responds cleanly to preflight OPTIONS requests
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],
  maxAge: 86400, // 24 hours
  preflightContinue: false,
};

// Rate limiting - general API
export const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    securityLog('RATE_LIMIT_EXCEEDED', { 
      ip: req.ip, 
      path: req.path,
      userAgent: req.headers['user-agent']
    });
    res.status(429).json({
      success: false,
      error: 'Too many requests, please try again later.'
    });
  },
  skip: (req) => process.env.NODE_ENV === 'development' && req.path === '/api/health'
});

// Stricter rate limiting for auth endpoints
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX) || 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    securityLog('AUTH_RATE_LIMIT_EXCEEDED', { 
      ip: req.ip, 
      email: req.body?.email,
      userAgent: req.headers['user-agent']
    });
    res.status(429).json({
      success: false,
      error: 'Too many login attempts. Please try again after 15 minutes.'
    });
  }
});

// Prevent NoSQL injection
export const sanitizeNoSQL = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    securityLog('NOSQL_INJECTION_ATTEMPT', {
      ip: req.ip,
      key,
      path: req.path
    });
  }
});

// Prevent HTTP Parameter Pollution
export const preventHPP = hpp({
  whitelist: ['category', 'type'] // Allow these to be arrays
});

// XSS Protection
export const xssProtection = xss();

// Request logging
export const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      requestId: req.id,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.headers['user-agent']?.substring(0, 100),
      userId: req.user?._id
    };
    
    if (res.statusCode >= 400) {
      logger.warn('HTTP_ERROR', logData);
    } else {
      logger.info('HTTP_REQUEST', logData);
    }
  });
  
  next();
};

// Error handling - don't leak stack traces in production
export const errorHandler = (err, req, res, next) => {
  const statusCode = err.status || err.statusCode || 500;
  
  // Log the full error internally
  logger.error('UNHANDLED_ERROR', {
    requestId: req.id,
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    ip: req.ip,
    path: req.path
  });

  // Don't leak sensitive error details in production
  const isDev = process.env.NODE_ENV === 'development';
  
  res.status(statusCode).json({
    success: false,
    error: statusCode === 500 && !isDev 
      ? 'Internal server error' 
      : err.message,
    ...(isDev && { stack: err.stack })
  });
};

// 404 handler
export const notFound = (req, res) => {
  res.status(404).json({
    success: false,
    error: `Route ${req.originalUrl} not found`
  });
};