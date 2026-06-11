// backend/seed.js
import mongoose from 'mongoose';
import User from './models/User.js';

await mongoose.connect('mongodb+srv://guercinho:Jupitere13@firstone.4pftj.mongodb.net/solutionTracker?retryWrites=true&w=majority&appName=FirstOne');

await User.create({
  name: 'Ralph Guerson Alcide',
  email: 'vision3855@gmail.com',
  password: "Jupitere13@",
  role: 'admin'
});
/* 
const managerPassword = await bcrypt.hash('manager123', 12);
await User.create({
  name: 'Manager User',
  email: 'manager@inventory.com',
  password: managerPassword,
  role: 'manager'
});

const staffPassword = await bcrypt.hash('staff123', 12);
await User.create({
  name: 'Staff User',
  email: 'staff@inventory.com',
  password: staffPassword,
  role: 'staff'
}); */

console.log('Users created!');
process.exit();