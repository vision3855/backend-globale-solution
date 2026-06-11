import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import connectDB from './config/db.js';
import { 
  securityHeaders, 
  apiLimiter, 
  sanitizeNoSQL, 
  preventHPP, 
  xssProtection,
  requestId,
  requestLogger,
  errorHandler,
  notFound
} from './middleware/security.js'; // 1. Removed corsOptions from import to use local configuration
import authRoutes from './routes/auth.js';
import productRoutes from './routes/products.js';
import transactionRoutes from './routes/transactions.js';
import dashboardRoutes from './routes/dashboard.js';

dotenv.config();

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

connectDB();

const app = express();
app.set('trust proxy', 1);

// 2. Explicit Local CORS Configuration
const allowedOrigins = [
  'http://localhost:3000',
  'https://globale-solution-fe.vercel.app'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

// 3. CORRECT MIDDLEWARE ORDER: CORS MUST GO FIRST
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Explicitly handle preflight across all routes

// Remaining Security middleware
app.use(requestId);
app.use(securityHeaders); 
app.use(apiLimiter);
app.use(cookieParser());
app.use(express.json({ limit: '10kb' })); 
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(sanitizeNoSQL);
app.use(xssProtection);
app.use(preventHPP);
app.use(requestLogger);

// Health check
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