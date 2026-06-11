import express from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { protect, restrictTo, revokeToken, generateToken, generateRefreshToken, logout } from '../middleware/auth.js';
import { loginValidator, registerValidator, handleValidationErrors } from '../utils/validators.js';
import { auditLog, securityLog } from '../utils/logger.js';
import { authLimiter } from '../middleware/security.js';
import { body, param } from 'express-validator';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Register (Admin only)
router.post('/register', protect, registerValidator, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      auditLog('UNAUTHORIZED_REGISTER_ATTEMPT', req.user, {
        ip: req.ip,
        targetEmail: req.body.email
      });
      return res.status(403).json({ success: false, error: 'Only admin can register new users' });
    }

    const { name, email, password, role } = req.body;

    const userExists = await User.findOne({ email: email.toLowerCase() });
    if (userExists) {
      return res.status(409).json({ success: false, error: 'User already exists' });
    }

    const user = await User.create({
      name,
      email: email.toLowerCase(),
      password,
      role: role || 'staff'
    });

    auditLog('USER_REGISTERED', req.user, {
      ip: req.ip,
      newUserId: user._id,
      newUserEmail: user.email,
      newUserRole: user.role
    });

    res.status(201).json({
      success: true,
      data: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    securityLog('REGISTER_ERROR', { error: error.message, ip: req.ip });
    res.status(400).json({ success: false, error: error.message });
  }
});

// Login with rate limiting and account lockout
router.post('/login', authLimiter, loginValidator, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() }).select('+password +loginAttempts +lockUntil');

    if (!user) {
      securityLog('LOGIN_FAILED_USER_NOT_FOUND', { email: email.toLowerCase(), ip: req.ip });
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    if (user.isLocked()) {
      securityLog('LOGIN_ATTEMPT_LOCKED_ACCOUNT', { 
        userId: user._id, 
        email: user.email, 
        ip: req.ip 
      });
      return res.status(423).json({ 
        success: false, 
        error: 'Account is temporarily locked due to too many failed attempts. Try again in 2 hours.' 
      });
    }

    const isMatch = await user.comparePassword(password);
    
    if (!isMatch) {
      await user.incLoginAttempts();
      securityLog('LOGIN_FAILED_WRONG_PASSWORD', { 
        userId: user._id, 
        email: user.email, 
        ip: req.ip,
        attempts: user.loginAttempts + 1
      });
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    if (!user.isActive) {
      securityLog('LOGIN_FAILED_INACTIVE', { userId: user._id, email: user.email, ip: req.ip });
      return res.status(401).json({ success: false, error: 'Account has been deactivated' });
    }

    if (user.loginAttempts > 0) {
      await user.updateOne({
        $set: { loginAttempts: 0, lastLogin: Date.now(), lastLoginIp: req.ip },
        $unset: { lockUntil: 1 }
      });
    } else {
      await user.updateOne({
        $set: { lastLogin: Date.now(), lastLoginIp: req.ip }
      });
    }

    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    auditLog('USER_LOGIN_SUCCESS', user, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      data: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        token
      }
    });
  } catch (error) {
    securityLog('LOGIN_ERROR', { error: error.message, ip: req.ip });
    res.status(500).json({ success: false, error: 'Authentication failed' });
  }
});

// Refresh token
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({ success: false, error: 'No refresh token' });
    }

    const decoded = jwt.verify(refreshToken, JWT_SECRET, {
      issuer: 'inventory-api',
      audience: 'inventory-client'
    });

    if (decoded.type !== 'refresh') {
      return res.status(401).json({ success: false, error: 'Invalid token type' });
    }

    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, error: 'User not found or inactive' });
    }

    const newToken = generateToken(user._id);
    
    res.json({
      success: true,
      data: { token: newToken }
    });
  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid refresh token' });
  }
});

// Get current user
router.get('/me', protect, async (req, res) => {
  res.json({
    success: true,
    data: {
      _id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role
    }
  });
});

// Logout
router.post('/logout', protect, (req, res) => {
  logout(req, res);
});

// Get all users (Admin/Manager only)
router.get('/users', protect, async (req, res) => {
  try {
    if (!['admin', 'manager'].includes(req.user.role)) {
      auditLog('UNAUTHORIZED_USER_LIST_ACCESS', req.user, { ip: req.ip });
      return res.status(403).json({ success: false, error: 'Access denied' });
    }

    const users = await User.find({ isActive: true })
      .select('-password -passwordResetToken -passwordResetExpires')
      .sort({ createdAt: -1 });

    res.json({ success: true, count: users.length, data: users });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update user role (Admin only)
router.put('/users/:id/role', protect, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      auditLog('UNAUTHORIZED_ROLE_CHANGE', req.user, { 
        ip: req.ip,
        targetUserId: req.params.id
      });
      return res.status(403).json({ success: false, error: 'Only admin can change roles' });
    }

    const { role } = req.body;
    const targetUser = await User.findById(req.params.id);

    if (!targetUser) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    if (targetUser._id.toString() === req.user._id.toString() && role !== 'admin') {
      return res.status(400).json({ success: false, error: 'Cannot change your own admin role' });
    }

    targetUser.role = role;
    await targetUser.save();

    auditLog('USER_ROLE_CHANGED', req.user, {
      ip: req.ip,
      targetUserId: targetUser._id,
      targetUserEmail: targetUser.email,
      oldRole: targetUser.role,
      newRole: role
    });

    res.json({ 
      success: true, 
      data: {
        _id: targetUser._id,
        name: targetUser.name,
        email: targetUser.email,
        role: targetUser.role
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Change password (with validation)
router.put('/change-password', 
  protect,
  [
    body('currentPassword')
      .notEmpty()
      .withMessage('Current password is required')
      .isLength({ max: 128 })
      .withMessage('Password too long'),
    body('newPassword')
      .isLength({ min: 8, max: 128 })
      .withMessage('New password must be between 8 and 128 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
      .withMessage('Password must contain uppercase, lowercase, number, and special character'),
    body('confirmPassword')
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error('Passwords do not match');
        }
        return true;
      }),
    handleValidationErrors
  ],
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user._id;

      const user = await User.findById(userId).select('+password');

      if (!user) {
        return res.status(404).json({ success: false, error: 'User not found' });
      }

      const isMatch = await user.comparePassword(currentPassword);
      if (!isMatch) {
        securityLog('PASSWORD_CHANGE_FAILED_WRONG_CURRENT', { email: user.email, ip: req.ip });
        return res.status(401).json({ success: false, error: 'Current password is incorrect' });
      }

      const isSamePassword = await user.comparePassword(newPassword);
      if (isSamePassword) {
        return res.status(400).json({ success: false, error: 'New password cannot be the same as the current password' });
      }

      user.password = newPassword;
      await user.save();

      const token = generateToken(user._id);
      const refreshToken = generateRefreshToken(user._id);

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      securityLog('PASSWORD_CHANGED_SUCCESS', { email: user.email, ip: req.ip });

      res.json({
        success: true,
        message: 'Password changed successfully',
        data: {
          token
        }
      });
    } catch (error) {
      securityLog('PASSWORD_CHANGE_ERROR', { error: error.message });
      res.status(500).json({ success: false, error: error.message });
    }
  }
);

// ADMIN: Force password reset for any user (Admin only)
router.post('/users/:id/reset-password',
  protect,
  restrictTo('admin'),
  [
    param('id').isMongoId().withMessage('Invalid user ID'),
    body('newPassword')
      .isLength({ min: 8, max: 128 })
      .withMessage('Password must be between 8 and 128 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/),
    handleValidationErrors
  ],
  async (req, res) => {
    try {
      const { id } = req.params;
      const { newPassword } = req.body;

      const user = await User.findById(id).select('+password');
      if (!user) {
        return res.status(404).json({ success: false, error: 'User not found' });
      }

      user.password = newPassword;
      await user.save();

      securityLog('ADMIN_RESET_USER_PASSWORD', { adminEmail: req.user.email, targetUser: user.email });

      res.json({
        success: true,
        message: 'Password reset successfully. User must log in again.'
      });
    } catch (error) {
      res.status(500).json({ success: false, error: 'Failed to reset password' });
    }
  }
);

export default router;