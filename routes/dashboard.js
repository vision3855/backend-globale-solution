import express from 'express';
import Product from '../models/Product.js';
import Transaction from '../models/Transaction.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

router.use(protect);

router.get('/stats', async (req, res) => {
  try {
    // Parallel queries for performance
    const [
      totalProducts,
      lowStockProducts,
      outOfStockProducts,
      todayTransactions,
      products,
      recentTransactions,
      monthlyData
    ] = await Promise.all([
      Product.countDocuments({ isActive: true }),
      Product.find({
        isActive: true,
        $expr: { $lte: ['$quantity', '$minStockLevel'] }
      }).limit(10),
      Product.find({ isActive: true, quantity: 0 }).limit(10),
      Transaction.find({ 
        date: { $gte: new Date().setHours(0, 0, 0, 0) } 
      }),
      Product.find({ isActive: true }).select('purchasePrice sellingPrice quantity'),
      Transaction.find()
        .populate('product', 'name sku')
        .sort({ date: -1 })
        .limit(10),
      Transaction.aggregate([
        {
          $match: {
            type: 'sale',
            date: { $gte: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000) }
          }
        },
        {
          $group: {
            _id: {
              year: { $year: '$date' },
              month: { $month: '$date' }
            },
            totalSales: { $sum: '$totalAmount' },
            count: { $sum: 1 }
          }
        },
        { $sort: { '_id.year': 1, '_id.month': 1 } },
        { $limit: 6 }
      ])
    ]);

    const todaySales = todayTransactions
      .filter(t => t.type === 'sale')
      .reduce((sum, t) => sum + t.totalAmount, 0);

    const todayPurchases = todayTransactions
      .filter(t => t.type === 'purchase')
      .reduce((sum, t) => sum + t.totalAmount, 0);

    const totalInventoryValue = products.reduce((sum, p) => sum + (p.purchasePrice * p.quantity), 0);
    const totalPotentialRevenue = products.reduce((sum, p) => sum + (p.sellingPrice * p.quantity), 0);

    res.json({
      success: true,
      data: {
        totalProducts,
        lowStockCount: lowStockProducts.length,
        outOfStockCount: outOfStockProducts.length,
        todaySales,
        todayPurchases,
        todayTransactionCount: todayTransactions.length,
        totalInventoryValue,
        totalPotentialRevenue,
        recentTransactions,
        monthlyTrend: monthlyData,
        lowStockProducts: lowStockProducts.map(p => ({
          id: p._id,
          name: p.name,
          quantity: p.quantity,
          minStockLevel: p.minStockLevel
        }))
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch dashboard data' });
  }
});

export default router;