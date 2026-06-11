import mongoose from 'mongoose';

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Product name is required'],
    trim: true,
    maxlength: [200, 'Name cannot exceed 200 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  sku: {
    type: String,
    required: [true, 'SKU is required'],
    unique: true,
    trim: true,
    uppercase: true,
    maxlength: [50, 'SKU cannot exceed 50 characters']
  },
  category: {
    type: String,
    required: [true, 'Category is required'],
    trim: true,
    maxlength: [100, 'Category cannot exceed 100 characters']
  },
  purchasePrice: {
    type: Number,
    required: [true, 'Purchase price is required'],
    min: [0, 'Price cannot be negative'],
    max: [1000000, 'Price exceeds maximum']
  },
  sellingPrice: {
    type: Number,
    required: [true, 'Selling price is required'],
    min: [0, 'Price cannot be negative'],
    max: [1000000, 'Price exceeds maximum']
  },
  quantity: {
    type: Number,
    required: [true, 'Quantity is required'],
    default: 0,
    min: [0, 'Quantity cannot be negative'],
    max: [1000000, 'Quantity exceeds maximum']
  },
  minStockLevel: {
    type: Number,
    default: 10,
    min: [0, 'Minimum stock cannot be negative'],
    max: [1000000, 'Exceeds maximum']
  },
  unit: {
    type: String,
    default: 'pcs',
    trim: true,
    maxlength: [20, 'Unit cannot exceed 20 characters']
  },
  supplier: {
    type: String,
    trim: true,
    maxlength: [200, 'Supplier name cannot exceed 200 characters']
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Security: Prevent direct modification of critical fields
productSchema.pre('save', function(next) {
  // Ensure quantity is integer
  if (this.quantity) this.quantity = Math.floor(this.quantity);
  if (this.minStockLevel) this.minStockLevel = Math.floor(this.minStockLevel);
  next();
});

// Indexes for performance
//productSchema.index({ sku: 1 });
productSchema.index({ category: 1 });
productSchema.index({ name: 'text', description: 'text' });
productSchema.index({ isActive: 1, quantity: 1 });

// Virtuals
productSchema.virtual('stockStatus').get(function() {
  if (this.quantity === 0) return 'out-of-stock';
  if (this.quantity <= this.minStockLevel) return 'low-stock';
  return 'in-stock';
});

productSchema.virtual('potentialProfit').get(function() {
  return (this.sellingPrice - this.purchasePrice) * this.quantity;
});

productSchema.set('toJSON', { virtuals: true });

const Product = mongoose.model('Product', productSchema);
export default Product;