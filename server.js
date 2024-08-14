const express = require('express');
const multer = require('multer');
const mysql = require('mysql2');
const path = require('path');
const fs = require('fs');
const ejs = require('ejs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // Middleware for handling cookies

const app = express();
const port = 2000;

// MySQL connection setup
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456789',
    database: 'file_upload'
});

// Connect to MySQL database
db.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        throw err;
    }
    console.log('Connected to MySQL database');
});

// JWT secret key
const SECRET_KEY = 'your_jwt_secret_key';

// Multer setup for file handling (disk storage)
const uploadPath = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadPath)) {
    fs.mkdirSync(uploadPath);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage: storage });

// Middleware setup
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser()); // Middleware for cookies
app.use(express.static('public')); // Serve static files from 'public' directory

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.sendStatus(401); // No token

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token
        req.user = user;
        next();
    });
};

// Route definitions
app.get('/', (req, res) => {
    res.render('user-login'); // Ensure 'user-login.ejs' exists in the 'views' folder
});

app.get('/admin/login', (req, res) => {
    res.render('admin-login'); // Ensure 'admin-login.ejs' exists in the 'views' folder
});

app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM admins WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Internal server error.');
        }

        if (results.length === 0) {
            return res.status(400).send('Invalid credentials.');
        }

        const admin = results[0];

        bcrypt.compare(password, admin.password, (err, match) => {
            if (err) {
                console.error('Bcrypt error:', err);
                return res.status(500).send('Internal server error.');
            }

            if (!match) {
                return res.status(400).send('Invalid credentials.');
            }

            const token = jwt.sign({ id: admin.id, role: 'admin' }, SECRET_KEY, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
            res.redirect('/admin/home');
        });
    });
});

app.get('/admin/register', (req, res) => res.render('admin-register'));

app.post('/admin/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Server error.');
        db.query('INSERT INTO admins (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
            if (err) return res.status(500).send('Database error.');
            res.redirect('/admin/login');
        });
    });
});

app.get('/admin/home', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403); // Forbidden for non-admins
    const query = 'SELECT id, title, purpose, language, filename FROM files';
    db.query(query, (err, results) => {
        if (err) return res.status(500).send('Database error.');
        res.render('home', { files: results }); // Ensure 'home.ejs' exists in the 'views' folder
    });
});

app.post('/admin/upload', authenticateToken, upload.single('fileUpload'), (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403); // Forbidden for non-admins
    if (!req.file) return res.status(400).send('No file uploaded.');
    const { title, purpose, language } = req.body;
    const { originalname, filename } = req.file;
    const query = 'INSERT INTO files (title, purpose, language, filename, file_path) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [title, purpose, language, originalname, filename], (err) => {
        if (err) return res.status(500).send('Database error.');
        res.redirect('/files');
    });
});

// User routes
app.get('/user/login', (req, res) => res.render('user-login')); // Ensure 'user-login.ejs' exists in the 'views' folder

app.post('/user/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err || results.length === 0) return res.status(400).send('Invalid credentials.');
        const user = results[0];
        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) return res.status(400).send('Invalid credentials.');
            const token = jwt.sign({ id: user.id, role: 'user' }, SECRET_KEY, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
            res.redirect('/files');
        });
    });
});

app.get('/user/register', (req, res) => res.render('user-register')); // Ensure 'user-register.ejs' exists in the 'views' folder

app.post('/user/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Server error.');
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
            if (err) return res.status(500).send('Database error.');
            res.redirect('/user/login');
        });
    });
});

app.get('/files', authenticateToken, (req, res) => {
    const query = 'SELECT id, title, purpose, language, filename, upload_date FROM files';
    db.query(query, (err, results) => {
        if (err) return res.status(500).send('Database error.');
        res.render('files', { 
            files: results,
            userRole: req.user.role // Pass the user's role to the EJS template
        });
    });
});

app.get('/files/edit/:id', authenticateToken, (req, res) => {
    const fileId = req.params.id;
    const query = 'SELECT * FROM files WHERE id = ?';
    db.query(query, [fileId], (err, results) => {
        if (err) return res.status(500).send('Database error.');
        if (results.length === 0) return res.status(404).send('File not found.');
        res.render('edit-file', { file: results[0] }); // Ensure 'edit-file.ejs' exists in the 'views' folder
    });
});

app.post('/files/edit/:id', authenticateToken, upload.single('fileUpload'), (req, res) => {
    const fileId = req.params.id;
    const { title, purpose, language } = req.body;
    let query = 'UPDATE files SET title = ?, purpose = ?, language = ?';
    const queryParams = [title, purpose, language];

    if (req.file) {
        query += ', filename = ?, file_path = ?';
        queryParams.push(req.file.originalname, req.file.filename);
    }

    query += ' WHERE id = ?';
    queryParams.push(fileId);

    db.query(query, queryParams, (err) => {
        if (err) return res.status(500).send('Database error.');
        res.redirect('/files');
    });
});

app.post('/files/delete/:id', authenticateToken, (req, res) => {
    const fileId = req.params.id;

    // Fetch the file info to remove the file from disk
    const query = 'SELECT filename FROM files WHERE id = ?';
    db.query(query, [fileId], (err, results) => {
        if (err) return res.status(500).send('Database error.');
        if (results.length === 0) return res.status(404).send('File not found.');

        const fileName = results[0].filename;
        const filePath = path.join(uploadPath, fileName);

        // Remove file from the disk
        fs.unlink(filePath, (err) => {
            if (err) return res.status(500).send('File deletion error.');

            // Remove file record from the database
            const deleteQuery = 'DELETE FROM files WHERE id = ?';
            db.query(deleteQuery, [fileId], (err) => {
                if (err) return res.status(500).send('Database error.');
                res.redirect('/files');
            });
        });
    });
});

// File download route
app.get('/uploads/:filename', authenticateToken, (req, res) => {
    const fileName = req.params.filename;
    const filePath = path.join(uploadPath, fileName);
    if (fs.existsSync(filePath)) {
        res.download(filePath, fileName, err => {
            if (err) {
                console.error('File download error:', err);
                res.status(500).send('File download error.');
            }
        });
    } else {
        res.status(404).send('File not found.');
    }
});
app.get('/admin-list-file', authenticateToken, (req, res) => {
    // Query the database for files, or any other logic
    const query = 'SELECT id, title, purpose, language, filename FROM files';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error.');
        }
        res.render('admin-list-file', { files: results }); // Ensure 'admin-list-file.ejs' exists in the 'views' folder
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
