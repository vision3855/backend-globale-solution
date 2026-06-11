import { body, param, query, validationResult } from 'express-validator';

// Sanitization helpers
const sanitizeString = (field) => body(field)
  .trim()
  .escape()
  .isLength({ min: 1, max: 200 })
  .withMessage(`${field} must be between 1 and 200 characters`);

const sanitizeEmail = () => body('email')
  .isEmail()
  .normalizeEmail()
  .isLength({ max: 100 })
  .withMessage('Invalid email format');

const sanitizePassword = () => body('password')
  .isLength({ min: 8, max: 128 })
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
  .withMessage('Password must be at least 8 characters with uppercase, lowercase, number and special character');

// Validation result handler
export const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Log validation failures for security monitoring
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
};

// Auth validators
export const loginValidator = [
  sanitizeEmail(),
  body('password').isLength({ min: 1, max: 128 }).withMessage('Password required'),
  handleValidationErrors
];

export const registerValidator = [
  sanitizeString('name'),
  sanitizeEmail(),
  sanitizePassword(),
  body('role').optional().isIn(['admin', 'manager', 'staff']).withMessage('Invalid role'),
  handleValidationErrors
];

// Product validators
export const productValidator = [
  sanitizeString('name'),
  body('sku').trim().escape().isAlphanumeric().isLength({ min: 3, max: 50 }).withMessage('Invalid SKU'),
  sanitizeString('category'),
  body('description').optional().trim().escape().isLength({ max: 1000 }),
  body('purchasePrice').isFloat({ min: 0, max: 1000000 }).withMessage('Invalid purchase price'),
  body('sellingPrice').isFloat({ min: 0, max: 1000000 }).withMessage('Invalid selling price'),
  body('quantity').isInt({ min: 0, max: 1000000 }).withMessage('Invalid quantity'),
  body('minStockLevel').optional().isInt({ min: 0, max: 1000000 }),
  body('unit').optional().trim().escape().isLength({ max: 20 }),
  body('supplier').optional().trim().escape().isLength({ max: 200 }),
  handleValidationErrors
];

// Transaction validators
export const transactionValidator = [
  body('type').isIn(['sale', 'purchase', 'return', 'adjustment']).withMessage('Invalid transaction type'),
  body('product').isMongoId().withMessage('Invalid product ID'),
  body('quantity').isInt({ min: 1, max: 100000 }).withMessage('Invalid quantity'),
  body('unitPrice').isFloat({ min: 0, max: 1000000 }).withMessage('Invalid unit price'),
  body('customerName').optional().trim().escape().isLength({ max: 200 }),
  body('supplierName').optional().trim().escape().isLength({ max: 200 }),
  body('notes').optional().trim().escape().isLength({ max: 1000 }),
  handleValidationErrors
];

// ID parameter validator
export const idValidator = [
  param('id').isMongoId().withMessage('Invalid ID format'),
  handleValidationErrors
];

// Query validators
export const productQueryValidator = [
  query('search').optional().trim().escape().isLength({ max: 100 }),
  query('category').optional().trim().escape().isLength({ max: 100 }),
  query('stockStatus').optional().isIn(['in-stock', 'low-stock', 'out-of-stock']),
  handleValidationErrors
];

// Pagination validator
export const paginationValidator = [
  query('page').optional().isInt({ min: 1, max: 10000 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  handleValidationErrors
];