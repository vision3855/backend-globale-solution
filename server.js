import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import connectDB from './config/db.js';
import { 
  securityHeaders, 
  corsOptions, 
  apiLimiter, 
  sanitizeNoSQL, 
  preventHPP, 
  xssProtection,
  requestId,
  requestLogger,
  errorHandler,
  notFound
} from './middleware/security.js';
import authRoutes from './routes/auth.js';
import productRoutes from './routes/products.js';
import transactionRoutes from './routes/transactions.js';
import dashboardRoutes from './routes/dashboard.js';

// Load env vars
dotenv.config();

// Validate critical environment variables
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`FATAL: Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET must be at least 32 characters');
  process.exit(1);
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Connect to database
connectDB();

const app = express();

// Trust proxy if behind reverse proxy (nginx, etc.)
app.set('trust proxy', 1);

// Security middleware - ORDER MATTERS
app.use(requestId);
app.use(securityHeaders);
app.use(cors(corsOptions));
app.use(apiLimiter);
app.use(cookieParser());
app.use(express.json({ limit: '10kb' })); // Prevent large payload attacks
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(sanitizeNoSQL);
app.use(xssProtection);
app.use(preventHPP);
app.use(requestLogger);

// Health check (no rate limit in dev)
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/products', productRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/dashboard', dashboardRoutes);

// Error handling
app.use(notFound);
app.use(errorHandler);

// Graceful shutdown
const server = app.listen(process.env.PORT || 5000, () => {
  console.log(`Server running in ${process.env.NODE_ENV} mode on port ${process.env.PORT || 5000}`);
});

process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION:', err.message);
  server.close(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err.message);
  server.close(() => process.exit(1));
});