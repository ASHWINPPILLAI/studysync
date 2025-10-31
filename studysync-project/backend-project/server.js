const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); 
require('dotenv').config(); // MUST BE AT THE TOP

const User = require('./models/user.model'); 
const Class = require('./models/class.model'); 

const app = express();

// --- Middleware ---
app.use(cors({ origin: 'http://localhost:5173' })); 
app.use(express.json()); 

// --- Database Seeding ---
const seedDatabase = async () => {
    try {
        // 1. Seed Admin
        const adminEmail = 'admin@studysync.com';
        let adminUser = await User.findOne({ email: adminEmail });
        if (!adminUser) {
            console.log("No Admin found. Creating initial Admin account...");
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash('admin123!', salt);
            adminUser = new User({
                name: 'System Admin',
                email: adminEmail,
                password: hashedPassword,
                role: 'admin'
            });
            await adminUser.save();
            console.log("Initial Admin created successfully.");
        }

        // 2. Seed a Demo Class
        let demoClass = await Class.findOne({ name: 'Demo Class' });
        if (!demoClass) {
            console.log("No Demo Class found. Creating...");
            demoClass = new Class({ name: 'Demo Class' });
            await demoClass.save();
            console.log("Demo Class created.");
        }

        // 3. Seed Teacher and assign to Demo Class
        const teacherEmail = 'teacher@studysync.com';
        let teacherUser = await User.findOne({ email: teacherEmail });
        if (!teacherUser) {
            console.log("No Demo Teacher found. Creating initial Teacher account...");
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash('teacher123!', salt);
            
            teacherUser = new User({
                name: 'Demo Teacher',
                email: teacherEmail,
                password: hashedPassword,
                role: 'teacher',
                classIds: [demoClass._id] // Assign to Demo Class
            });
            await teacherUser.save();
            console.log("Initial Teacher created and assigned to Demo Class.");
        }

        // 4. Seed a Demo Student and assign to Demo Class
        const studentEmail = 'user@studysync.com';
        let studentUser = await User.findOne({ email: studentEmail });
        if (!studentUser) {
            console.log("No Demo Student found. Creating initial Student account...");
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash('user123!', salt);
            
            studentUser = new User({
                name: 'Demo Student',
                email: studentEmail,
                password: hashedPassword,
                role: 'user',
                classId: demoClass._id // Assign to Demo Class
            });
            await studentUser.save();
            console.log("Initial Student created and assigned to Demo Class.");
        }

    } catch (error) {
        console.error("Database Seeding Error:", error.message);
    }
};

// --- Database Connection ---
const uri = process.env.MONGO_URI;
mongoose.connect(uri)
  .then(() => {
    console.log("MongoDB connected");
    seedDatabase(); // Run the seed function upon successful connection
  })
  .catch(err => console.log(err));

// --- API Routes ---
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/users', require('./routes/user.routes'));
app.use('/api/classes', require('./routes/class.routes'));
app.use('/api/subjects', require('./routes/subject.routes'));
app.use('/api/marks', require('./routes/mark.routes'));
app.use('/api/materials', require('./routes/material.routes'));

// --- Start Server ---
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});