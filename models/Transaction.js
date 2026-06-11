import mongoose from 'mongoose';

const transactionSchema = new mongoose.Schema({
  product: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: [true, 'Product is required'],
    index: true
  },
  type: {
    type: String,
    enum: {
      values: ['sale', 'purchase', 'return', 'adjustment'],
      message: 'Transaction type must be sale, purchase, return, or adjustment'
    },
    required: [true, 'Transaction type is required']
  },
  quantity: {
    type: Number,
    required: [true, 'Quantity is required'],
    min: [1, 'Quantity must be at least 1'],
    max: [999999, 'Quantity too high']
  },
  unitPrice: {
    type: Number,
    required: [true, 'Unit price is required'],
    min: [0, 'Unit price cannot be negative'],
    max: [999999, 'Unit price too high']
  },
  totalAmount: {
    type: Number,
    required: false,  // <-- CHANGED: Not required, computed automatically
    min: [0, 'Total amount cannot be negative']
  },
  customerName: {
    type: String,
    trim: true,
    maxlength: [100, 'Customer name cannot exceed 100 characters']
  },
  supplierName: {
    type: String,
    trim: true,
    maxlength: [100, 'Supplier name cannot exceed 100 characters']
  },
  notes: {
    type: String,
    trim: true,
    maxlength: [500, 'Notes cannot exceed 500 characters']
  },
  performedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Transaction performer is required']
  },
  date: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for performance
transactionSchema.index({ product: 1, date: -1 });
transactionSchema.index({ type: 1 });
transactionSchema.index({ date: -1 });

// Pre-validate hook: compute totalAmount BEFORE validation runs
transactionSchema.pre('validate', function(next) {
  if (this.quantity != null && this.unitPrice != null) {
    this.totalAmount = this.quantity * this.unitPrice;
  }
  next();
});

// Pre-save hook: ensure totalAmount is set (fallback)
transactionSchema.pre('save', function(next) {
  if (this.quantity != null && this.unitPrice != null) {
    this.totalAmount = this.quantity * this.unitPrice;
  }
  next();
});

const Transaction = mongoose.model('Transaction', transactionSchema);
export default Transaction;