import express from 'express';
import Product from '../models/Product.js';
import { protect, readOnlyForStaff } from '../middleware/auth.js';
import { productValidator, idValidator, productQueryValidator } from '../utils/validators.js';
import { auditLog } from '../utils/logger.js';

const router = express.Router();

router.use(protect);

router.get('/', productQueryValidator, async (req, res) => {
  try {
    const { search, category, stockStatus, page = 1, limit = 50 } = req.query;
    
    // Build query safely
    let query = { isActive: true };

    if (search) {
      // Use text search if available, otherwise regex
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { sku: { $regex: search, $options: 'i' } }
      ];
    }

    if (category) query.category = category;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [products, total] = await Promise.all([
      Product.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      Product.countDocuments(query)
    ]);

    let filteredProducts = products;
    if (stockStatus) {
      filteredProducts = products.filter(p => p.stockStatus === stockStatus);
    }

    res.json({
      success: true,
      count: filteredProducts.length,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit)),
      data: filteredProducts
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch products' });
  }
});

router.get('/:id', idValidator, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product || !product.isActive) {
      return res.status(404).json({ success: false, error: 'Product not found' });
    }
    res.json({ success: true, data: product });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch product' });
  }
});

router.post('/', readOnlyForStaff, productValidator, async (req, res) => {
  try {
    const product = await Product.create({
      ...req.body,
      createdBy: req.user._id
    });

    auditLog('PRODUCT_CREATED', req.user, {
      ip: req.ip,
      productId: product._id,
      productName: product.name
    });

    res.status(201).json({ success: true, data: product });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ success: false, error: 'SKU already exists' });
    }
    res.status(400).json({ success: false, error: error.message });
  }
});

router.put('/:id', readOnlyForStaff, idValidator, productValidator, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { ...req.body, updatedBy: req.user._id },
      { new: true, runValidators: true }
    );
    
    if (!product) {
      return res.status(404).json({ success: false, error: 'Product not found' });
    }

    auditLog('PRODUCT_UPDATED', req.user, {
      ip: req.ip,
      productId: product._id,
      productName: product.name
    });

    res.json({ success: true, data: product });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ success: false, error: 'SKU already exists' });
    }
    res.status(400).json({ success: false, error: error.message });
  }
});

router.delete('/:id', readOnlyForStaff, idValidator, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { isActive: false, updatedBy: req.user._id },
      { new: true }
    );
    
    if (!product) {
      return res.status(404).json({ success: false, error: 'Product not found' });
    }

    auditLog('PRODUCT_DELETED', req.user, {
      ip: req.ip,
      productId: product._id,
      productName: product.name
    });

    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to delete product' });
  }
});

router.get('/meta/categories', async (req, res) => {
  try {
    const categories = await Product.distinct('category', { isActive: true });
    res.json({ success: true, data: categories });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch categories' });
  }
});

export default router;