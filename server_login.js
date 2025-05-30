// server.js
require('dotenv').config(); // Memuat variabel lingkungan dari file .env

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const cors = require('cors'); // Import modul cors untuk menangani Cross-Origin Resource Sharing

// --- Inisialisasi Lingkungan ---

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
// Pastikan file HTML Anda (login_page.html, register_page.html) berada di dalam folder 'public'.
app.use(express.static(path.join(__dirname, 'public')));

// --- Konfigurasi Koneksi Database MySQL ---
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0 // Menambahkan queueLimit untuk konsistensi, meskipun 0 adalah default
});

// --- Inisialisasi Database (Membuat Tabel Pengguna Jika Belum Ada) ---
async function initDB() {
    let conn;
    try {
        conn = await pool.getConnection();
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
    } catch (error) {
        console.error('Error initializing database:', error.message);
        process.exit(1); // Keluar dari proses jika inisialisasi DB gagal
    } finally {
        if (conn) conn.release(); // Pastikan koneksi dilepaskan
    }
}

// --- API Routes ---

// Route Pendaftaran Pengguna
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validasi input dasar
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nama, email, dan password wajib diisi.' });
        }
        if (password.length < 6) { // Contoh: minimal panjang password
            return res.status(400).json({ error: 'Password minimal 6 karakter.' });
        }

        // Memeriksa apakah email sudah terdaftar
        const [users] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (users.length > 0) {
            return res.status(409).json({ error: 'Email sudah terdaftar.' });
        }

        // Melakukan hashing password untuk keamanan
        const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds: 10

        // Memasukkan pengguna baru ke database
        await pool.query(
            'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
            [name, email, hashedPassword]
        );

        console.log(`Pengguna terdaftar: ${email}`);
        res.status(201).json({ success: true, message: 'Pendaftaran berhasil!' });

    } catch (error) {
        console.error('Error pendaftaran:', error);
        res.status(500).json({ error: 'Terjadi kesalahan server saat pendaftaran.' });
    }
});

// Route Login Pengguna
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validasi input dasar
        if (!email || !password) {
            return res.status(400).json({ error: 'Email dan password wajib diisi.' });
        }

        // Mencari pengguna berdasarkan email
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Kredensial tidak valid (email atau password salah).' });
        }

        // Memeriksa password
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Kredensial tidak valid (email atau password salah).' });
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
        res.status(500).json({ error: 'Terjadi kesalahan server saat login.' });
    }
});

// Middleware otentikasi untuk rute yang dilindungi
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // Memastikan token ada dan dimulai dengan 'Bearer '
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json({ error: 'Akses ditolak. Token tidak disediakan.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Verifikasi token gagal:', err.message);
            // Mengembalikan 403 (Forbidden) untuk token yang tidak valid/kadaluarsa
            return res.status(403).json({ error: 'Token tidak valid atau kadaluarsa.' });
        }
        req.user = user; // Menambahkan payload user dari token ke objek request
        next(); // Lanjutkan ke route handler berikutnya
    });
};

// Contoh Route yang Dilindungi (hanya bisa diakses dengan token yang valid)
app.get('/api/protected', authenticateToken, async (req, res) => {
    try {
        // req.user berisi payload dari token (misalnya { userId: user.id })
        const [users] = await pool.query('SELECT id, name, email FROM users WHERE id = ?', [req.user.userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
        }
        res.json({ message: 'Anda berhasil mengakses rute yang dilindungi!', user: users[0] });
    } catch (error) {
        console.error('Error mengakses rute dilindungi:', error);
        res.status(500).json({ error: 'Terjadi kesalahan server.' });
    }
});

// --- Route untuk Halaman Frontend (Redirects) ---
// Mengarahkan root URL '/' ke halaman login
app.get('/', (req, res) => {
    res.redirect('/login_page.html'); // Mengarahkan ke file HTML statis
});

// Mengarahkan /login ke halaman login_page.html
app.get('/login', (req, res) => {
    res.redirect('/login_page.html');
});

// Mengarahkan /register ke halaman register_page.html
app.get('/register', (req, res) => {
    res.redirect('/register_page.html');
});

// --- Memulai Server ---
async function startServer() {
    await initDB(); // Inisialisasi database sebelum memulai server
    const port = process.env.PORT || 5000;
    app.listen(port, () => {
        console.log(`Server berjalan di http://localhost:${port}`);
        console.log('Endpoints API:');
        console.log(`- POST /api/register (body: { name, email, password })`);
        console.log(`- POST /api/login (body: { email, password })`);
        console.log(`- GET /api/protected (Header: Authorization: Bearer <token>)`);
        console.log('\nAkses halaman frontend melalui:');
        console.log(`- http://localhost:${port}/login_page.html`);
        console.log(`- http://localhost:${port}/register_page.html`);
    });
}

startServer();
