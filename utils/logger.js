import winston from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const { combine, timestamp, json, errors } = winston.format;

// Security-sensitive log filter - never log passwords, tokens, or PII
const sanitizeLog = winston.format((info) => {
  const sensitiveFields = ['password', 'token', 'authorization', 'cookie', 'jwt', 'secret', 'creditCard', 'ssn'];
  const sanitized = { ...info };
  
  const sanitizeObject = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    for (const key of Object.keys(obj)) {
      const lowerKey = key.toLowerCase();
      if (sensitiveFields.some(f => lowerKey.includes(f))) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object') {
        sanitizeObject(obj[key]);
      }
    }
  };
  
  sanitizeObject(sanitized);
  return sanitized;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  defaultMeta: { service: 'inventory-api' },
  format: combine(
    timestamp(),
    sanitizeLog(),
    json()
  ),
  transports: [
    new winston.transports.Console({
      format: process.env.NODE_ENV === 'development' 
        ? winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        : undefined
    }),
    // Security audit log
    new winston.transports.File({ 
      filename: path.join(__dirname, '../logs/security-audit.log'),
      level: 'warn'
    }),
    // General application log
    new winston.transports.File({ 
      filename: path.join(__dirname, '../logs/app.log') 
    }),
  ],
  // Don't crash on uncaught exceptions, log them
  exitOnError: false,
});

// Security audit helper
export const auditLog = (action, user, details = {}) => {
  logger.warn('SECURITY_AUDIT', {
    action,
    userId: user?._id,
    userEmail: user?.email,
    userRole: user?.role,
    ip: details.ip,
    userAgent: details.userAgent,
    timestamp: new Date().toISOString(),
    ...details
  });
};

export const securityLog = (event, details = {}) => {
  logger.error('SECURITY_EVENT', {
    event,
    timestamp: new Date().toISOString(),
    ...details
  });
};

export default logger;