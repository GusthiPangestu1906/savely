// server.js
// Memuat variabel lingkungan dari file .env.
// Ini harus menjadi baris pertama di file Anda.
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise'); // Menggunakan mysql2 dengan dukungan Promise
const bcrypt = require('bcryptjs'); // Untuk hashing password
const jwt = require('jsonwebtoken'); // Untuk JSON Web Tokens
const fs = require('fs'); // Untuk operasi sistem file (membuat .env)
const path = require('path'); // Untuk menangani jalur file
const cors = require('cors'); // Untuk menangani Cross-Origin Resource Sharing

// --- Inisialisasi Lingkungan dan Konfigurasi ---

// Membuat file .env jika tidak ada.
// CATATAN PENTING: Untuk produksi, variabel lingkungan harus diatur secara eksternal,
// bukan dibuat secara otomatis oleh aplikasi. Ini hanya untuk kemudahan pengembangan lokal.
const envPath = path.join(__dirname, '.env');
if (!fs.existsSync(envPath)) {
    // Pastikan JWT_SECRET ini diganti dengan string yang sangat kuat dan acak di lingkungan produksi!
    // Anda bisa menggunakan alat seperti `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
    // untuk membuat secret yang kuat.
    fs.writeFileSync(envPath, `DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=savely_db
JWT_SECRET=your_super_secret_jwt_key_please_change_this_to_a_strong_random_string
PORT=5000`);
    console.log('.env file created. Please configure your database settings and change JWT_SECRET.');
}

// Mengambil PORT dari variabel lingkungan atau menggunakan default 5000
const PORT = process.env.PORT || 5000;

// --- Konfigurasi Aplikasi Express ---
const app = express();

// Middleware untuk menangani CORS.
// Ini memungkinkan permintaan dari asal yang berbeda (misalnya, jika frontend Anda diakses langsung dari file:// atau domain lain).
app.use(cors());

// Middleware untuk mengurai body permintaan dalam format JSON
app.use(express.json());
// Middleware untuk mengurai body permintaan dalam format URL-encoded (penting untuk formulir HTML)
app.use(express.urlencoded({ extended: true }));

// Melayani file statis dari direktori 'public'.
// Pastikan file HTML Anda (login_page.html, register_page.html, targeting_page.html, budgetary_targeting.html)
// berada di dalam folder 'public'.
app.use(express.static(path.join(__dirname, 'public')));

// --- Konfigurasi Koneksi Database MySQL ---
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10, // Jumlah maksimum koneksi yang dapat dibuat oleh pool
    queueLimit: 0 // Jumlah maksimum permintaan yang dapat di-queue jika semua koneksi sedang digunakan
});

// --- Inisialisasi Database (Membuat Tabel Pengguna, Target, Transaksi, dan Pesan Kontak Jika Belum Ada) ---
async function initDB() {
    let conn;
    try {
        conn = await pool.getConnection(); // Mendapatkan koneksi dari pool

        // Membuat tabel 'users' jika belum ada
        await conn.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Database table "users" ready or already exists.');

        // Membuat tabel 'targets' jika belum ada
        // Menambahkan user_id sebagai foreign key untuk mengaitkan target dengan pengguna
        await conn.query(`
            CREATE TABLE IF NOT EXISTS targets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                type ENUM('savings', 'expense', 'income') NOT NULL,
                amount DECIMAL(15, 2) NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL,
                progress DECIMAL(5, 2) DEFAULT 0.00,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
        console.log('Database table "targets" ready or already exists.');

        // Membuat tabel 'transactions' jika belum ada
        await conn.query(`
            CREATE TABLE IF NOT EXISTS transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                type ENUM('income', 'expense') NOT NULL,
                category VARCHAR(255) NOT NULL,
                amount DECIMAL(15, 2) NOT NULL,
                date DATE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
        console.log('Database table "transactions" ready or already exists.');

        // Membuat tabel 'contact_messages' untuk menyimpan pesan dari formulir kontak
        await conn.query(`
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('Database table "contact_messages" ready or already exists.');

    } catch (error) {
        console.error('Error initializing database:', error.message);
        // Keluar dari proses jika inisialisasi DB gagal karena ini kritis
        process.exit(1);
    } finally {
        if (conn) conn.release(); // Pastikan koneksi dilepaskan kembali ke pool
    }
}

// --- Helper Functions untuk API Target & Transaksi ---

// Fungsi untuk memvalidasi data target
const validateTarget = (target) => {
    const errors = [];

    if (!target.title || target.title.trim().length === 0) {
        errors.push('Title is required');
    }

    if (!target.type || !['income', 'expense', 'savings'].includes(target.type)) {
        errors.push('Type must be income, expense, or savings');
    }

    // Menggunakan parseFloat untuk memastikan amount adalah angka
    if (isNaN(parseFloat(target.amount)) || parseFloat(target.amount) <= 0) {
        errors.push('Amount must be a positive number');
    }

    if (!target.startDate) {
        errors.push('Start date is required');
    }

    if (!target.endDate) {
        errors.push('End date is required');
    }

    if (target.startDate && target.endDate && new Date(target.startDate) >= new Date(target.endDate)) {
        errors.push('End date must be after start date');
    }

    // Menggunakan parseFloat untuk memastikan progress adalah angka
    if (target.progress !== undefined && (isNaN(parseFloat(target.progress)) || parseFloat(target.progress) < 0 || parseFloat(target.progress) > 100)) {
        errors.push('Progress must be between 0 and 100');
    }

    return errors;
};

// Fungsi untuk memvalidasi data transaksi
const validateTransaction = (transaction) => {
    const errors = [];

    if (!transaction.type || !['income', 'expense'].includes(transaction.type)) {
        errors.push('Transaction type must be income or expense');
    }

    if (!transaction.category || transaction.category.trim().length === 0) {
        errors.push('Category is required');
    }

    if (isNaN(parseFloat(transaction.amount)) || parseFloat(transaction.amount) <= 0) {
        errors.push('Amount must be a positive number');
    }

    if (!transaction.date) {
        errors.push('Date is required');
    }

    return errors;
};

// Fungsi untuk memformat respons API secara konsisten
const formatResponse = (success, data = null, message = '', errors = []) => {
    return {
        success,
        data,
        message,
        errors,
        timestamp: new Date().toISOString()
    };
};

// --- Middleware Otentikasi JWT ---

// Middleware untuk memverifikasi token JWT pada rute yang dilindungi
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // Memastikan token ada dan dimulai dengan 'Bearer '
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json(formatResponse(false, null, 'Akses ditolak. Token tidak disediakan.'));
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Verifikasi token gagal:', err.message);
            // Mengembalikan 403 (Forbidden) untuk token yang tidak valid/kadaluarsa
            return res.status(403).json(formatResponse(false, null, 'Token tidak valid atau kadaluarsa.'));
        }
        req.user = user; // Menambahkan payload user dari token ke objek request
        next(); // Lanjutkan ke route handler berikutnya
    });
};

// --- API Routes (Otentikasi) ---

// Route Pendaftaran Pengguna
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validasi input dasar
        if (!name || !email || !password) {
            return res.status(400).json(formatResponse(false, null, 'Nama, email, dan password wajib diisi.'));
        }
        if (password.length < 6) { // Contoh: minimal panjang password
            return res.status(400).json(formatResponse(false, null, 'Password minimal 6 karakter.'));
        }

        // Memeriksa apakah email sudah terdaftar
        const [users] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (users.length > 0) {
            return res.status(409).json(formatResponse(false, null, 'Email sudah terdaftar.'));
        }

        // Melakukan hashing password untuk keamanan
        const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds: 10

        // Memasukkan pengguna baru ke database
        await pool.query(
            'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
            [name, email, hashedPassword]
        );

        console.log(`Pengguna terdaftar: ${email}`);
        res.status(201).json(formatResponse(true, null, 'Pendaftaran berhasil!'));

    } catch (error) {
        console.error('Error pendaftaran:', error);
        res.status(500).json(formatResponse(false, null, 'Terjadi kesalahan server saat pendaftaran.', [error.message]));
    }
});

// Endpoint untuk menerima pesan kontak dari landing page
app.post('/api/contact-message', async (req, res) => {
    try {
        const { name, email, message } = req.body;

        // Validasi data input
        if (!name || name.trim() === '' || !email || email.trim() === '' || !message || message.trim() === '') {
            return res.status(400).json(formatResponse(false, null, 'Nama, email, dan pesan wajib diisi.'));
        }
        // Validasi format email sederhana
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json(formatResponse(false, null, 'Format email tidak valid.'));
        }
        // Batasan panjang pesan
        if (message.length > 1000) {
            return res.status(400).json(formatResponse(false, null, 'Pesan terlalu panjang (maksimal 1000 karakter).'));
        }


        // Menyimpan pesan ke tabel 'contact_messages'
        await pool.query(
            'INSERT INTO contact_messages (name, email, message, created_at) VALUES (?, ?, ?, NOW())',
            [name, email, message]
        );

        console.log(`Pesan kontak baru diterima dari ${name} (${email}): ${message}`);
        res.status(200).json(formatResponse(true, null, 'Terima kasih! Pesan Anda telah kami terima.'));

    } catch (error) {
        console.error('Error saat menerima pesan kontak:', error);
        res.status(500).json(formatResponse(false, null, 'Terjadi kesalahan server saat mengirim pesan.', [error.message]));
    }
});

// Route Login Pengguna
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validasi input dasar
        if (!email || !password) {
            return res.status(400).json(formatResponse(false, null, 'Email dan password wajib diisi.'));
        }

        // Mencari pengguna berdasarkan email
        const [users] = await pool.query('SELECT id, name, email, password FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json(formatResponse(false, null, 'Kredensial tidak valid (email atau password salah).'));
        }

        // Memeriksa password
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json(formatResponse(false, null, 'Kredensial tidak valid (email atau password salah).'));
        }

        // Membuat JSON Web Token (JWT)
        const token = jwt.sign(
            { userId: user.id },
            process.env.JWT_SECRET, // Menggunakan secret dari .env
            { expiresIn: '1h' } // Token akan kadaluarsa dalam 1 jam
        );

        console.log(`Pengguna berhasil login: ${email}`);
        res.status(200).json({
            success: true,
            message: 'Login berhasil!',
            token, // Mengirim token ke frontend
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error login:', error);
        res.status(500).json(formatResponse(false, null, 'Terjadi kesalahan server saat login.', [error.message]));
    }
});

// Contoh Route yang Dilindungi (hanya bisa diakses dengan token yang valid)
app.get('/api/protected', authenticateToken, async (req, res) => {
    try {
        // req.user berisi payload dari token (misalnya { userId: user.id })
        const [users] = await pool.query('SELECT id, name, email FROM users WHERE id = ?', [req.user.userId]);
        if (users.length === 0) {
            return res.status(404).json(formatResponse(false, null, 'Pengguna tidak ditemukan.'));
        }
        res.json(formatResponse(true, users[0], 'Anda berhasil mengakses rute yang dilindungi!'));
    } catch (error) {
        console.error('Error mengakses rute dilindungi:', error);
        res.status(500).json(formatResponse(false, null, 'Terjadi kesalahan server.', [error.message]));
    }
});

// --- API Routes (Manajemen Target Keuangan) ---

// GET /api/targets - Mendapatkan semua target dengan pemfilteran opsional
app.get('/api/targets', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Mengambil user_id dari token yang diautentikasi
        const { type, search, sortBy, sortOrder } = req.query;

        let query = 'SELECT id, title, type, amount, start_date AS startDate, end_date AS endDate, progress, description, created_at AS createdAt, updated_at AS updatedAt FROM targets WHERE user_id = ?';
        const queryParams = [userId];

        if (type && type !== 'all') {
            query += ' AND type = ?';
            queryParams.push(type);
        }

        if (search) {
            query += ' AND (title LIKE ? OR description LIKE ?)';
            queryParams.push(`%${search}%`, `%${search}%`);
        }

        // Whitelist untuk kolom yang bisa diurutkan untuk mencegah SQL Injection
        const allowedSortBy = ['createdAt', 'endDate', 'amount', 'progress', 'title'];
        const finalSortBy = allowedSortBy.includes(sortBy) ? sortBy : 'createdAt'; // Default sort
        const finalSortOrder = (sortOrder === 'asc' || sortOrder === 'desc') ? sortOrder.toUpperCase() : 'DESC'; // Default order

        query += ` ORDER BY ${finalSortBy} ${finalSortOrder}`;

        const [targets] = await pool.query(query, queryParams);

        res.json(formatResponse(true, targets, 'Targets retrieved successfully'));
    } catch (error) {
        console.error('Error retrieving targets:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// GET /api/targets/:id - Mendapatkan satu target
app.get('/api/targets/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const targetId = parseInt(req.params.id);

        if (isNaN(targetId)) {
            return res.status(400).json(formatResponse(false, null, 'Invalid target ID.'));
        }

        const [targets] = await pool.query(
            'SELECT id, title, type, amount, start_date AS startDate, end_date AS endDate, progress, description, created_at AS createdAt, updated_at AS updatedAt FROM targets WHERE id = ? AND user_id = ?',
            [targetId, userId]
        );

        if (targets.length === 0) {
            return res.status(404).json(formatResponse(false, null, 'Target not found or not authorized.'));
        }

        res.json(formatResponse(true, targets[0], 'Target retrieved successfully'));
    } catch (error) {
        console.error('Error retrieving single target:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// POST /api/targets - Membuat target baru
app.post('/api/targets', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { title, type, amount, startDate, endDate, progress, description } = req.body;

        const targetData = { title, type, amount, startDate, endDate, progress, description };
        const validationErrors = validateTarget(targetData);
        if (validationErrors.length > 0) {
            return res.status(400).json(formatResponse(false, null, 'Validation failed', validationErrors));
        }

        const [result] = await pool.query(
            'INSERT INTO targets (user_id, title, type, amount, start_date, end_date, progress, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, title, type, amount, startDate, endDate, progress || 0, description || null]
        );

        // Mengambil target yang baru dibuat untuk dikirim kembali ke frontend
        const [newTarget] = await pool.query(
            'SELECT id, title, type, amount, start_date AS startDate, end_date AS endDate, progress, description, created_at AS createdAt, updated_at AS updatedAt FROM targets WHERE id = ?',
            [result.insertId]
        );

        res.status(201).json(formatResponse(true, newTarget[0], 'Target created successfully'));
    } catch (error) {
        console.error('Error creating target:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// PUT /api/targets/:id - Memperbarui target
app.put('/api/targets/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const targetId = parseInt(req.params.id);
        const { title, type, amount, startDate, endDate, progress, description } = req.body;

        if (isNaN(targetId)) {
            return res.status(400).json(formatResponse(false, null, 'Invalid target ID.'));
        }

        const targetData = { title, type, amount, startDate, endDate, progress, description };
        const validationErrors = validateTarget(targetData);
        if (validationErrors.length > 0) {
            return res.status(400).json(formatResponse(false, null, 'Validation failed', validationErrors));
        }

        const [result] = await pool.query(
            'UPDATE targets SET title = ?, type = ?, amount = ?, start_date = ?, end_date = ?, progress = ?, description = ? WHERE id = ? AND user_id = ?',
            [title, type, amount, startDate, endDate, progress, description || null, targetId, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json(formatResponse(false, null, 'Target not found or not authorized to update.'));
        }

        // Mengambil target yang diperbarui untuk dikirim kembali ke frontend
        const [updatedTarget] = await pool.query(
            'SELECT id, title, type, amount, start_date AS startDate, end_date AS endDate, progress, description, created_at AS createdAt, updated_at AS updatedAt FROM targets WHERE id = ?',
            [targetId]
        );

        res.json(formatResponse(true, updatedTarget[0], 'Target updated successfully'));
    } catch (error) {
        console.error('Error updating target:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// PATCH /api/targets/:id/progress - Memperbarui hanya progres
app.patch('/api/targets/:id/progress', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const targetId = parseInt(req.params.id);
        const { progress } = req.body;

        if (isNaN(targetId)) {
            return res.status(400).json(formatResponse(false, null, 'Invalid target ID.'));
        }

        const progressValue = parseFloat(progress);
        if (isNaN(progressValue) || progressValue < 0 || progressValue > 100) {
            return res.status(400).json(formatResponse(false, null, 'Validation failed', ['Progress must be between 0 and 100']));
        }

        const [result] = await pool.query(
            'UPDATE targets SET progress = ? WHERE id = ? AND user_id = ?',
            [progressValue, targetId, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json(formatResponse(false, null, 'Target not found or not authorized to update progress.'));
        }

        // Mengambil target yang diperbarui untuk dikirim kembali ke frontend
        const [updatedTarget] = await pool.query(
            'SELECT id, title, type, amount, start_date AS startDate, end_date AS endDate, progress, description, created_at AS createdAt, updated_at AS updatedAt FROM targets WHERE id = ?',
            [targetId]
        );

        res.json(formatResponse(true, updatedTarget[0], 'Progress updated successfully'));
    } catch (error) {
        console.error('Error updating progress:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// DELETE /api/targets/:id - Menghapus target
app.delete('/api/targets/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const targetId = parseInt(req.params.id);

        if (isNaN(targetId)) {
            return res.status(400).json(formatResponse(false, null, 'Invalid target ID.'));
        }

        const [result] = await pool.query(
            'DELETE FROM targets WHERE id = ? AND user_id = ?',
            [targetId, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json(formatResponse(false, null, 'Target not found or not authorized to delete.'));
        }

        res.json(formatResponse(true, null, 'Target deleted successfully'));
    } catch (error) {
        console.error('Error deleting target:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// GET /api/stats - Mendapatkan statistik target
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Mengambil statistik dari database
        const [statsResult] = await pool.query(`
            SELECT
                COUNT(id) AS totalTargets,
                SUM(CASE WHEN type = 'savings' THEN amount ELSE 0 END) AS totalSavings,
                SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) AS totalExpenses,
                SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) AS totalIncome,
                AVG(progress) AS averageProgress,
                SUM(CASE WHEN progress >= 100 THEN 1 ELSE 0 END) AS completedTargets,
                SUM(CASE WHEN progress > 0 AND progress < 100 THEN 1 ELSE 0 END) AS inProgressTargets,
                SUM(CASE WHEN progress = 0 THEN 1 ELSE 0 END) AS notStartedTargets,
                SUM(CASE WHEN type = 'savings' THEN 1 ELSE 0 END) AS savingsCount,
                SUM(CASE WHEN type = 'expense' THEN 1 ELSE 0 END) AS expenseCount,
                SUM(CASE WHEN type = 'income' THEN 1 ELSE 0 END) AS incomeCount
            FROM targets
            WHERE user_id = ?
        `, [userId]);

        const stats = statsResult[0];

        // Memformat ulang hasil untuk konsistensi dengan formatResponse
        const formattedStats = {
            totalTargets: stats.totalTargets || 0,
            totalSavings: parseFloat(stats.totalSavings) || 0,
            totalExpenses: parseFloat(stats.totalExpenses) || 0,
            totalIncome: parseFloat(stats.totalIncome) || 0,
            averageProgress: parseFloat(stats.averageProgress) || 0,
            completedTargets: stats.completedTargets || 0,
            inProgressTargets: stats.inProgressTargets || 0,
            notStartedTargets: stats.notStartedTargets || 0,
            targetsByType: {
                savings: stats.savingsCount || 0,
                expense: stats.expenseCount || 0,
                income: stats.incomeCount || 0
            }
        };

        res.json(formatResponse(true, formattedStats, 'Statistics retrieved successfully'));
    } catch (error) {
        console.error('Error retrieving stats:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// --- API Routes (Manajemen Transaksi) ---

// GET /api/transactions - Mendapatkan semua transaksi untuk pengguna yang diautentikasi
app.get('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { type, search, sortBy, sortOrder } = req.query;

        let query = 'SELECT id, type, category, amount, date, description, created_at AS createdAt, updated_at AS updatedAt FROM transactions WHERE user_id = ?';
        const queryParams = [userId];

        if (type && type !== 'all' && ['income', 'expense'].includes(type)) {
            query += ' AND type = ?';
            queryParams.push(type);
        }

        if (search) {
            query += ' AND (category LIKE ? OR description LIKE ?)';
            queryParams.push(`%${search}%`, `%${search}%`);
        }

        const allowedSortBy = ['createdAt', 'date', 'amount', 'category'];
        const finalSortBy = allowedSortBy.includes(sortBy) ? sortBy : 'date'; 
        const finalSortOrder = (sortOrder === 'asc' || sortOrder === 'desc') ? sortOrder.toUpperCase() : 'DESC'; 

        query += ` ORDER BY ${finalSortBy} ${finalSortOrder}`;

        const [transactions] = await pool.query(query, queryParams);

        res.json(formatResponse(true, transactions, 'Transactions retrieved successfully'));
    } catch (error) {
        console.error('Error retrieving transactions:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// GET /api/transactions/:id - Mendapatkan satu transaksi berdasarkan ID
app.get('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const transactionId = parseInt(req.params.id);

        if (isNaN(transactionId)) {
            return res.status(400).json(formatResponse(false, null, 'Invalid transaction ID.'));
        }

        const [transactions] = await pool.query(
            'SELECT id, type, category, amount, date, description, created_at AS createdAt, updated_at AS updatedAt FROM transactions WHERE id = ? AND user_id = ?',
            [transactionId, userId]
        );

        if (transactions.length === 0) {
            return res.status(404).json(formatResponse(false, null, 'Transaction not found or not authorized.'));
        }

        res.json(formatResponse(true, transactions[0], 'Transaction retrieved successfully'));
    } catch (error) {
        console.error('Error retrieving single transaction:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// POST /api/transactions - Membuat transaksi baru
app.post('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { type, category, amount, date, description } = req.body;

        const transactionData = { type, category, amount, date, description };
        const validationErrors = validateTransaction(transactionData);
        if (validationErrors.length > 0) {
            return res.status(400).json(formatResponse(false, null, 'Validation failed', validationErrors));
        }

        const [result] = await pool.query(
            'INSERT INTO transactions (user_id, type, category, amount, date, description) VALUES (?, ?, ?, ?, ?, ?)',
            [userId, type, category, amount, date, description || null]
        );

        const [newTransaction] = await pool.query(
            'SELECT id, type, category, amount, date, description, created_at AS createdAt, updated_at AS updatedAt FROM transactions WHERE id = ?',
            [result.insertId]
        );

        res.status(201).json(formatResponse(true, newTransaction[0], 'Transaction created successfully'));
    } catch (error) {
        console.error('Error creating transaction:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// PUT /api/transactions/:id - Memperbarui transaksi
app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const transactionId = parseInt(req.params.id);
        const { type, category, amount, date, description } = req.body;

        if (isNaN(transactionId)) {
            return res.status(400).json(formatResponse(false, null, 'Invalid transaction ID.'));
        }

        const transactionData = { type, category, amount, date, description };
        const validationErrors = validateTransaction(transactionData);
        if (validationErrors.length > 0) {
            return res.status(400).json(formatResponse(false, null, 'Validation failed', validationErrors));
        }

        const [result] = await pool.query(
            'UPDATE transactions SET type = ?, category = ?, amount = ?, date = ?, description = ? WHERE id = ? AND user_id = ?',
            [type, category, amount, date, description || null, transactionId, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json(formatResponse(false, null, 'Transaction not found or not authorized to update.'));
        }

        const [updatedTransaction] = await pool.query(
            'SELECT id, type, category, amount, date, description, created_at AS createdAt, updated_at AS updatedAt FROM transactions WHERE id = ?',
            [transactionId]
        );

        res.json(formatResponse(true, updatedTransaction[0], 'Transaction updated successfully'));
    } catch (error) {
        console.error('Error updating transaction:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});

// DELETE /api/transactions/:id - Menghapus transaksi
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const transactionId = parseInt(req.params.id);

        if (isNaN(transactionId)) {
            return res.status(400).json(formatResponse(false, null, 'Invalid transaction ID.'));
        }

        const [result] = await pool.query(
            'DELETE FROM transactions WHERE id = ? AND user_id = ?',
            [transactionId, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json(formatResponse(false, null, 'Transaction not found or not authorized to delete.'));
        }

        res.json(formatResponse(true, null, 'Transaction deleted successfully'));
    } catch (error) {
        console.error('Error deleting transaction:', error);
        res.status(500).json(formatResponse(false, null, 'Internal server error', [error.message]));
    }
});


// --- Route untuk Halaman Frontend (Redirects) ---
// Mengarahkan root URL '/' ke halaman landing page
app.get('/', (req, res) => {
    res.redirect('/landing_page.html'); // Mengarahkan ke file HTML statis landing page
});

// Mengarahkan /login ke halaman login_page.html
app.get('/login', (req, res) => {
    res.redirect('/login_page.html');
});

// Baris ini dihapus karena menyebabkan loop pengalihan:
// app.get('/dashboard.html', (req, res) => {
//     res.redirect('/dashboard.html');
// });

// Mengarahkan /register ke halaman register_page.html
app.get('/register', (req, res) => {
    res.redirect('/register_page.html');
});

// Mengarahkan /targets ke halaman targeting_page.html
app.get('/targets', (req, res) => {
    res.redirect('/targeting_page.html');
});

// Mengarahkan /budgetary-targeting ke halaman budgetary_targeting.html
app.get('/budgetary-targeting', (req, res) => {
    res.redirect('/budgetary_targeting.html');
});

// Mengarahkan /transactions ke halaman transactions.html
app.get('/transactions', (req, res) => {
    res.redirect('/transactions.html');
});


// --- Middleware Penanganan Error Global ---
// Middleware ini akan menangkap error yang tidak tertangkap di route handler
app.use((err, req, res, next) => {
    console.error(err.stack); // Mencatat stack trace error ke konsol server
    res.status(500).json(formatResponse(false, null, 'Terjadi kesalahan server!', [err.message]));
});

// --- Middleware 404 (Not Found) ---
// Middleware ini akan dijalankan jika tidak ada route yang cocok
app.use((req, res) => {
    res.status(404).json(formatResponse(false, null, 'Endpoint tidak ditemukan.'));
});

// --- Memulai Server ---
async function startServer() {
    await initDB(); // Inisialisasi database sebelum memulai server
    app.listen(PORT, () => {
        console.log(`Server berjalan di http://localhost:${PORT}`);
        console.log('Endpoints API Otentikasi:');
        console.log(`- POST /api/register (body: { name, email, password })`);
        console.log(`- POST /api/login (body: { email, password })`);
        console.log(`- GET /api/protected (Header: Authorization: Bearer <token>)`);
        console.log('\nEndpoints API Manajemen Target (membutuhkan token JWT):');
        console.log(`- GET /api/targets`);
        console.log(`- GET /api/targets/:id`);
        console.log(`- POST /api/targets (body: { title, type, amount, startDate, endDate, progress?, description? })`);
        console.log(`- PUT /api/targets/:id (body: { title, type, amount, startDate, endDate, progress?, description? })`);
        console.log(`- PATCH /api/targets/:id/progress (body: { progress })`);
        console.log(`- DELETE /api/targets/:id`);
        console.log(`- GET /api/stats`);
        console.log('\nEndpoints API Manajemen Transaksi (membutuhkan token JWT):');
        console.log(`- GET /api/transactions`);
        console.log(`- GET /api/transactions/:id`);
        console.log(`- POST /api/transactions (body: { type, category, amount, date, description? })`);
        console.log(`- PUT /api/transactions/:id (body: { type, category, amount, date, description? })`);
        console.log(`- DELETE /api/transactions/:id`);
        console.log('\nEndpoint API Lainnya:');
        console.log(`- POST /api/contact-message (body: { name, email, message })`); 
        console.log('\nAkses halaman frontend melalui:');
        console.log(`- http://localhost:${PORT}/landing_page.html`); 
        console.log(`- http://localhost:${PORT}/login_page.html`);
        console.log(`- http://localhost:${PORT}/dashboard.html`);
        console.log(`- http://localhost:${PORT}/register_page.html`);
        console.log(`- http://localhost:${PORT}/targeting_page.html`);
        console.log(`- http://localhost:${PORT}/budgetary-targeting`);
        console.log(`- http://localhost:${PORT}/transactions`); 
    });
}

startServer(); // Panggil fungsi untuk memulai server
