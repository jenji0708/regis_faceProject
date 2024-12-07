// const express = require('express');
// const mongoose = require('mongoose');
// const jwt = require('jsonwebtoken');
// const multer = require('multer');
// const bcrypt = require('bcrypt');
// const path = require('path');
// const bodyParser = require('body-parser');
// const cookieParser = require('cookie-parser');
// require('dotenv').config(); // Use environment variables

// const app = express();

// // Middleware setup
// app.use(express.static(path.join(__dirname, 'templates')));
// app.use(express.static(path.join(__dirname, 'public')));
// app.use(express.static(path.join(__dirname, 'static')));

// app.set('views', path.join(__dirname, 'templates')); // กำหนดตำแหน่งของ views
// app.set('view engine', 'ejs'); // ตั้งค่า view engine เป็น EJS (หรือ Pug ถ้าต้องการ)


// app.use(bodyParser.urlencoded({ extended: true }));
// app.use(bodyParser.json());
// app.use(cookieParser());

// // MongoDB connection
// mongoose.connect('mongodb://localhost:27017/user_database', { useNewUrlParser: true, useUnifiedTopology: true });

// // Define the User schema
// const userSchema = new mongoose.Schema({
//     firstname: String,
//     lastname: String,
//     student_id: { type: String, unique: true }, // Ensure student_id is unique
//     password: String,
//     face_encodings: [[Number]],
//     images: [String]
// });
// const User = mongoose.model('User', userSchema);

// // JWT Secret
// const JWT_SECRET = process.env.JWT_SECRET || 'mySuperSecretKey12345!';

// // Setup multer for image uploads
// const storage = multer.diskStorage({
//     destination: (req, file, cb) => {
//         cb(null, './templates/uploads'); // Store uploads in templates/uploads
//     },
//     filename: (req, file, cb) => {
//         const studentId = req.body.student_id;
//         cb(null, `${studentId}_${file.fieldname}.jpg`);
//     }
// });
// const upload = multer({ storage: storage });

// // Helper functions
// const generateToken = (userId) => {
//     const payload = { user_id: userId };
//     return jwt.sign(payload, JWT_SECRET, { expiresIn: '2h' });
// };

// const verifyToken = (token) => {
//     try {
//         const payload = jwt.verify(token, JWT_SECRET);
//         return payload.user_id;
//     } catch (error) {
//         return null;
//     }
// };
// // Registration route
// app.post('/register', async (req, res) => {
//     const { student_id, email, password, confirm_password } = req.body;

//     // Validate the password match
//     if (password !== confirm_password) {
//         return res.status(400).json({ success: false, message: 'Passwords do not match' });
//     }

//     // Hash the password
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Check if the user already exists
//     const existingUser = await User.findOne({ student_id });
//     if (existingUser) {
//         return res.status(400).json({ success: false, message: 'User already exists' });
//     }

//     // Create a new user
//     const user = new User({
//         student_id,
//         email,
//         password: hashedPassword
//     });

//     try {
//         await user.save();
//         return res.status(200).json({ success: true, message: 'Registration successful!' });
//     } catch (error) {
//         console.error('Error saving user:', error);
//         return res.status(500).json({ success: false, message: 'Internal Server Error' });
//     }
// });

// // Face registration route
// app.post('/register_face', upload.fields([{ name: 'imageFront' }, { name: 'imageLeft' }, { name: 'imageRight' }]), async (req, res) => {
//     const { firstname, lastname, student_id } = req.body;
//     const face_encodings = [];
//     const image_files = [];

//     // Process uploaded images
//     const imageFiles = [...req.files.imageFront, ...(req.files.imageLeft || []), ...(req.files.imageRight || [])];
//     for (let file of imageFiles) {
//         // Assuming face_recognition is defined and imported correctly
//         const image = face_recognition.loadImageFile(file.path);
//         const encoding = face_recognition.faceEncodings(image);

//         if (encoding.length === 0) {
//             return res.status(400).json({ message: 'No face detected. Please upload a clear image.' });
//         }
//         face_encodings.push(encoding[0].toString()); // Convert to string for storage
//         image_files.push(file.filename);
//     }

//     const user = new User({
//         firstname,
//         lastname,
//         student_id,
//         face_encodings,
//         images: image_files
//     });

//     await user.save();
//     res.redirect('/compare_face');
// });

// // Login route (GET)
// app.get('/auth/login', (req, res) => {
//     res.sendFile(path.join(__dirname, 'templates', 'login.html')); // Serve login.html
// });

// app.post('/auth/login', (req, res) => {
//     const { studentID, password } = req.body;

//     User.findOne({ student_id: studentID }, async (err, user) => {
//         if (err) return res.status(500).json({ success: false, message: 'Internal server error' });
//         if (!user) return res.status(404).json({ success: false, message: 'User not found' });

//         const isMatch = await bcrypt.compare(password, user.password);
//         if (isMatch) {
//             const token = generateToken(user.student_id);
//             res.cookie('jwt_token', token, { httpOnly: true });
//             return res.status(200).json({ success: true, message: 'Login successful' });
//         } else {
//             return res.status(401).json({ success: false, message: 'Incorrect password' });
//         }
//     });
// });



// // Logout route
// app.get('/auth/logout', (req, res) => {
//     res.clearCookie('jwt_token');
//     res.redirect('/login');
// });

// const authenticateToken = (req, res, next) => {
//     const token = req.cookies.jwt_token;
//     if (!token) {
//         return res.redirect('/login'); // If no token, redirect to login
//     }

//     try {
//         const decoded = jwt.verify(token, 'your_jwt_secret_key');
//         req.user = decoded;
//         next(); // Token is valid, proceed to next middleware/route
//     } catch (err) {
//         return res.redirect('/login'); // Invalid token, redirect to login
//     }
// };

// app.get('/home', (req, res) => {
//     res.sendFile(path.join(__dirname, 'templates', 'home.html')); // Serve the home page
// });


// // Other routes for serving pages
// app.get('/register', (req, res) => {
//     res.sendFile(path.join(__dirname, 'templates', 'register.html')); // Serve register.html
// });

// app.get('/showInformation', (req, res) => {
//     res.sendFile(path.join(__dirname, 'templates', 'showInformation.html')); // Serve showInformation.html
// });

// app.get('/address', (req, res) => {
//     res.sendFile(path.join(__dirname, 'templates', 'address.html')); // Serve address.html
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//     console.log(`Server is running on port ${PORT}`);
// });
