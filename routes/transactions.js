import express from 'express';
import mongoose from 'mongoose';
import Transaction from '../models/Transaction.js';
import Product from '../models/Product.js';
import { protect, readOnlyForStaff } from '../middleware/auth.js';
import { transactionValidator, idValidator } from '../utils/validators.js';
import { auditLog, securityLog } from '../utils/logger.js';

const router = express.Router();

router.use(protect);

router.get('/', async (req, res) => {
  try {
    const { product, type, startDate, endDate, page = 1, limit = 50 } = req.query;
    let query = {};

    if (product) {
      if (!mongoose.Types.ObjectId.isValid(product)) {
        return res.status(400).json({ success: false, error: 'Invalid product ID' });
      }
      query.product = product;
    }
    
    if (type) query.type = type;
    
    if (startDate || endDate) {
      query.date = {};
      if (startDate) {
        const date = new Date(startDate);
        if (isNaN(date.getTime())) {
          return res.status(400).json({ success: false, error: 'Invalid start date' });
        }
        query.date.$gte = date;
      }
      if (endDate) {
        const date = new Date(endDate);
        if (isNaN(date.getTime())) {
          return res.status(400).json({ success: false, error: 'Invalid end date' });
        }
        // Set to end of day
        date.setHours(23, 59, 59, 999);
        query.date.$lte = date;
      }
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .populate('product', 'name sku category')
        .sort({ date: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      Transaction.countDocuments(query)
    ]);

    res.json({
      success: true,
      count: transactions.length,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit)),
      data: transactions
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch transactions' });
  }
});

router.post('/', readOnlyForStaff, transactionValidator, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { product: productId, type, quantity, unitPrice, customerName, supplierName, notes } = req.body;

    const product = await Product.findById(productId).session(session);
    if (!product || !product.isActive) {
      throw new Error('Product not found or inactive');
    }

    // Validate business logic
    if (type === 'sale' || type === 'adjustment') {
      if (product.quantity < quantity) {
        throw new Error(`Insufficient stock. Available: ${product.quantity}, Requested: ${quantity}`);
      }
      product.quantity -= quantity;
    } else if (type === 'purchase') {
      // Prevent overflow
      if (product.quantity + quantity > 1000000) {
        throw new Error('Quantity would exceed maximum allowed');
      }
      product.quantity += quantity;
    } else if (type === 'return') {
      if (product.quantity + quantity > 1000000) {
        throw new Error('Quantity would exceed maximum allowed');
      }
      product.quantity += quantity;
    }

    await product.save({ session });

    const transaction = await Transaction.create([{
      product: productId,
      type,
      quantity,
      unitPrice,
      customerName,
      supplierName,
      notes,
      performedBy: req.user._id
    }], { session });

    await session.commitTransaction();

    const populatedTransaction = await Transaction.findById(transaction[0]._id)
      .populate('product', 'name sku');

    auditLog('TRANSACTION_CREATED', req.user, {
      ip: req.ip,
      transactionId: transaction[0]._id,
      type,
      productId,
      amount: transaction[0].totalAmount
    });

    res.status(201).json({
      success: true,
      data: populatedTransaction
    });
  } catch (error) {
    await session.abortTransaction();
    
    if (error.message.includes('Insufficient stock')) {
      return res.status(422).json({ success: false, error: error.message });
    }
    
    securityLog('TRANSACTION_ERROR', {
      error: error.message,
      userId: req.user._id,
      ip: req.ip
    });
    
    res.status(400).json({ success: false, error: error.message });
  } finally {
    session.endSession();
  }
});

router.get('/:id', idValidator, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id)
      .populate('product', 'name sku category purchasePrice sellingPrice');
    
    if (!transaction) {
      return res.status(404).json({ success: false, error: 'Transaction not found' });
    }
    
    res.json({ success: true, data: transaction });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch transaction' });
  }
});

export default router;