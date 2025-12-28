-- ============================================
-- DATABASE: rental_mobil - REVISI FINAL DENGAN MIDTRANS FULL
-- ============================================

-- Buat database jika belum ada
DROP DATABASE IF EXISTS rental_mobil;
CREATE DATABASE IF NOT EXISTS rental_mobil;
USE rental_mobil;

-- ============================================
-- TABEL: users (admin dan customer)
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    nama VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    nik VARCHAR(16) UNIQUE NOT NULL,
    alamat TEXT,
    no_telepon VARCHAR(15),
    tanggal_lahir DATE,
    role ENUM('admin', 'customer') DEFAULT 'customer',
    foto_profil VARCHAR(255),
    status ENUM('active', 'inactive', 'banned') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP NULL,
    last_login TIMESTAMP NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_nik (nik),
    INDEX idx_role (role),
    INDEX idx_status (status)
);

-- ============================================
-- TABEL: mobil
-- ============================================
CREATE TABLE IF NOT EXISTS mobil (
    id INT PRIMARY KEY AUTO_INCREMENT,
    merk VARCHAR(50) NOT NULL,
    model VARCHAR(50) NOT NULL,
    tahun INT NOT NULL,
    plat_nomor VARCHAR(15) UNIQUE NOT NULL,
    tipe ENUM('sedan', 'suv', 'mpv', 'hatchback', 'sport', 'truck') NOT NULL,
    transmisi ENUM('manual', 'automatic') DEFAULT 'automatic',
    kapasitas INT NOT NULL,
    harga_per_hari DECIMAL(10,2) NOT NULL,
    deskripsi TEXT,
    gambar VARCHAR(255),
    status ENUM('tersedia', 'disewa', 'maintenance') DEFAULT 'tersedia',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_tipe (tipe),
    INDEX idx_harga (harga_per_hari)
);

-- ============================================
-- TABEL: pesanan (REVISI DENGAN MIDTRANS - DIPERBAIKI)
-- ============================================
CREATE TABLE IF NOT EXISTS pesanan (
    id INT PRIMARY KEY AUTO_INCREMENT,
    kode_pesanan VARCHAR(20) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    mobil_id INT NOT NULL,
    tanggal_pemesanan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tanggal_mulai DATE NOT NULL,
    tanggal_selesai DATE NOT NULL,
    durasi_hari INT NOT NULL,
    total_harga DECIMAL(10,2) NOT NULL,
    lokasi_penjemputan TEXT,
    catatan TEXT,
    status ENUM('pending', 'diproses', 'dikonfirmasi', 'dibatalkan', 'selesai') DEFAULT 'pending',
    metode_pembayaran VARCHAR(50) DEFAULT 'midtrans',
    status_pembayaran ENUM('pending', 'paid', 'failed', 'expired') DEFAULT 'pending',
    
    -- Midtrans fields
    midtrans_token VARCHAR(255),
    midtrans_order_id VARCHAR(100),
    midtrans_transaction_status VARCHAR(50),
    payment_type VARCHAR(50),
    bank VARCHAR(50),
    va_number VARCHAR(50),
    transaction_time DATETIME,
    settlement_time DATETIME,
    
    -- Payment timestamp
    tanggal_pembayaran TIMESTAMP NULL,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign keys
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (mobil_id) REFERENCES mobil(id) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_kode_pesanan (kode_pesanan),
    INDEX idx_user_id (user_id),
    INDEX idx_status (status),
    INDEX idx_status_pembayaran (status_pembayaran),
    INDEX idx_tanggal_pemesanan (tanggal_pemesanan),
    INDEX idx_midtrans_token (midtrans_token),
    INDEX idx_midtrans_order (midtrans_order_id),
    INDEX idx_tanggal_pembayaran (tanggal_pembayaran)
);

-- ============================================
-- TABEL: pembayaran (REVISI - DIPERBAIKI)
-- ============================================
CREATE TABLE IF NOT EXISTS pembayaran (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pesanan_id INT NOT NULL,
    jumlah DECIMAL(10,2) NOT NULL,
    metode ENUM('bank_transfer', 'credit_card', 'qris', 'ewallet', 'midtrans') NOT NULL,
    status ENUM('pending', 'success', 'failed', 'expired', 'settlement', 'capture') DEFAULT 'pending',
    bukti_pembayaran VARCHAR(255),
    
    -- Payment details
    tanggal_pembayaran TIMESTAMP NULL,
    transaction_id VARCHAR(100),
    payment_type VARCHAR(50),
    bank VARCHAR(50),
    va_number VARCHAR(50),
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign key
    FOREIGN KEY (pesanan_id) REFERENCES pesanan(id) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_pesanan_id (pesanan_id),
    INDEX idx_status (status),
    INDEX idx_transaction_id (transaction_id),
    INDEX idx_tanggal_pembayaran (tanggal_pembayaran)
);

-- ============================================
-- TABEL: chat
-- ============================================
CREATE TABLE IF NOT EXISTS chat (
    id INT PRIMARY KEY AUTO_INCREMENT,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sender_receiver (sender_id, receiver_id),
    INDEX idx_receiver_sender (receiver_id, sender_id),
    INDEX idx_created_at (created_at),
    INDEX idx_is_read (is_read)
);

-- ============================================
-- TABEL: reviews
-- ============================================
CREATE TABLE IF NOT EXISTS reviews (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pesanan_id INT NOT NULL,
    user_id INT NOT NULL,
    mobil_id INT NOT NULL,
    rating INT CHECK (rating >= 1 AND rating <= 5),
    komentar TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pesanan_id) REFERENCES pesanan(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (mobil_id) REFERENCES mobil(id) ON DELETE CASCADE,
    INDEX idx_mobil_id (mobil_id),
    INDEX idx_user_id (user_id),
    INDEX idx_rating (rating)
);

-- ============================================
-- TABEL: midtrans_logs (BARU - untuk debugging)
-- ============================================
CREATE TABLE IF NOT EXISTS midtrans_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    order_id VARCHAR(100) NOT NULL,
    transaction_id VARCHAR(100),
    transaction_status VARCHAR(50),
    fraud_status VARCHAR(50),
    payment_type VARCHAR(50),
    bank VARCHAR(50),
    va_number VARCHAR(50),
    gross_amount DECIMAL(10,2),
    response_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_order_id (order_id),
    INDEX idx_transaction_id (transaction_id),
    INDEX idx_created_at (created_at)
);

-- ============================================
-- DATA AWAL (DUMMY DATA - DIPERBARUI)
-- ============================================

-- Insert default admin user (password: admin123)
INSERT INTO users (nama, email, password, nik, role, status, verified_at) 
VALUES (
    'Admin Rental',
    'admin@rental.com',
    '$2b$12$K9Q1cXr.5oW6e5YV8gLZJeh8Q8WqHjLmN8cV7vB6dF5gH3jK2LpO',
    '1234567890123456',
    'admin',
    'active',
    NOW()
);

-- Insert sample customer (password: customer123)
INSERT INTO users (nama, email, password, nik, no_telepon, alamat, tanggal_lahir, role, status, verified_at) 
VALUES (
    'Customer Demo',
    'customer@demo.com',
    '$2b$12$K9Q1cXr.5oW6e5YV8gLZJeh8Q8WqHjLmN8cV7vB6dF5gH3jK2LpO',
    '9876543210987654',
    '081234567890',
    'Jl. Contoh No. 123, Jakarta',
    '1990-01-01',
    'customer',
    'active',
    NOW()
);

-- Insert additional customer for testing
INSERT INTO users (nama, email, password, nik, no_telepon, alamat, tanggal_lahir, role, status, verified_at) 
VALUES (
    'John Doe',
    'john@demo.com',
    '$2b$12$K9Q1cXr.5oW6e5YV8gLZJeh8Q8WqHjLmN8cV7vB6dF5gH3jK2LpO',
    '1111222233334444',
    '081111222333',
    'Jl. Test No. 456, Bandung',
    '1995-05-15',
    'customer',
    'active',
    NOW()
);

-- Insert sample cars
INSERT INTO mobil (merk, model, tahun, plat_nomor, tipe, transmisi, kapasitas, harga_per_hari, deskripsi, gambar, status) VALUES
('Toyota', 'Avanza', 2022, 'B 1234 ABC', 'mpv', 'automatic', 7, 350000, 'Mobil keluarga dengan kenyamanan maksimal', 'avanza.jpg', 'tersedia'),
('Honda', 'Brio', 2023, 'B 5678 DEF', 'hatchback', 'automatic', 5, 250000, 'Mobil irit dan mudah dikendarai', 'brio.jpg', 'tersedia'),
('Mitsubishi', 'Pajero Sport', 2022, 'B 9012 GHI', 'suv', 'automatic', 7, 600000, 'SUV tangguh untuk segala medan', 'pajero.jpg', 'tersedia'),
('Toyota', 'Camry', 2023, 'B 3456 JKL', 'sedan', 'automatic', 5, 500000, 'Sedan mewah dengan fitur lengkap', 'camry.jpg', 'tersedia'),
('Daihatsu', 'Xenia', 2022, 'B 7890 MNO', 'mpv', 'manual', 7, 300000, 'Mobil keluarga ekonomis', 'xenia.jpg', 'tersedia'),
('BMW', 'X5', 2023, 'B 1111 BMW', 'suv', 'automatic', 5, 1200000, 'SUV mewah dengan performa tinggi', 'x5.jpg', 'tersedia'),
('Suzuki', 'Ertiga', 2022, 'B 2222 XYZ', 'mpv', 'automatic', 7, 320000, 'MPV dengan efisiensi bahan bakar terbaik', 'ertiga.jpg', 'tersedia'),
('Toyota', 'Fortuner', 2023, 'B 3333 RST', 'suv', 'automatic', 7, 750000, 'SUV tangguh dengan ground clearance tinggi', 'fortuner.jpg', 'tersedia'),
('Honda', 'Civic', 2023, 'B 4444 UVW', 'sedan', 'automatic', 5, 550000, 'Sedan sporty dengan performa tinggi', 'civic.jpg', 'tersedia'),
('Wuling', 'Almaz', 2022, 'B 5555 OPQ', 'suv', 'automatic', 7, 450000, 'SUV dengan teknologi canggih', 'almaz.jpg', 'tersedia');

-- Insert sample orders with Midtrans testing data
INSERT INTO pesanan (kode_pesanan, user_id, mobil_id, tanggal_mulai, tanggal_selesai, durasi_hari, total_harga, lokasi_penjemputan, status, status_pembayaran, metode_pembayaran) 
VALUES 
(
    'RENT-20240101-ABC123',
    2,
    1,
    DATE_ADD(CURDATE(), INTERVAL 2 DAY),
    DATE_ADD(CURDATE(), INTERVAL 5 DAY),
    4,
    1400000,
    'Jl. Sudirman No. 123, Jakarta',
    'dikonfirmasi',
    'paid',
    'midtrans'
),
(
    'RENT-20240102-DEF456',
    3,
    3,
    DATE_ADD(CURDATE(), INTERVAL 3 DAY),
    DATE_ADD(CURDATE(), INTERVAL 7 DAY),
    5,
    3000000,
    'Jl. Thamrin No. 45, Jakarta',
    'pending',
    'pending',
    'midtrans'
),
(
    'RENT-20240103-GHI789',
    2,
    5,
    DATE_ADD(CURDATE(), INTERVAL 1 DAY),
    DATE_ADD(CURDATE(), INTERVAL 3 DAY),
    3,
    900000,
    'Jl. Gatot Subroto No. 67, Jakarta',
    'pending',
    'pending',
    'midtrans'
);

-- Insert sample chat
INSERT INTO chat (sender_id, receiver_id, message, is_read) 
VALUES 
(2, 1, 'Halo admin, saya ingin bertanya tentang mobil Toyota Avanza', TRUE),
(1, 2, 'Halo, ada yang bisa saya bantu?', TRUE),
(2, 1, 'Apakah mobil tersebut tersedia untuk tanggal 15?', FALSE),
(3, 1, 'Mobil BMW X5 masih tersedia?', TRUE),
(1, 3, 'Ya, masih tersedia. Silakan booking melalui website kami.', FALSE);

-- ============================================
-- TRIGGERS (DIPERBAIKI TOTAL)
-- ============================================

DELIMITER //

-- Trigger untuk update timestamp otomatis
CREATE TRIGGER update_mobil_timestamp 
BEFORE UPDATE ON mobil
FOR EACH ROW
BEGIN
    SET NEW.updated_at = NOW();
END //

-- Trigger untuk generate kode pesanan otomatis
CREATE TRIGGER before_insert_pesanan
BEFORE INSERT ON pesanan
FOR EACH ROW
BEGIN
    IF NEW.kode_pesanan IS NULL OR NEW.kode_pesanan = '' THEN
        SET NEW.kode_pesanan = CONCAT('RENT-', DATE_FORMAT(NOW(), '%Y%m%d'), '-', 
            UPPER(SUBSTRING(MD5(RAND()), 1, 6)));
    END IF;
END //

-- Trigger untuk update mobil status ketika pesanan dibuat
CREATE TRIGGER after_insert_pesanan
AFTER INSERT ON pesanan
FOR EACH ROW
BEGIN
    IF NEW.status = 'pending' OR NEW.status = 'dikonfirmasi' THEN
        UPDATE mobil SET status = 'disewa' WHERE id = NEW.mobil_id;
    END IF;
END //

-- Trigger untuk update mobil status ketika pesanan selesai/dibatalkan
CREATE TRIGGER after_update_pesanan
AFTER UPDATE ON pesanan
FOR EACH ROW
BEGIN
    IF NEW.status IN ('selesai', 'dibatalkan') AND OLD.status NOT IN ('selesai', 'dibatalkan') THEN
        UPDATE mobil SET status = 'tersedia' WHERE id = NEW.mobil_id;
    END IF;
END //

-- ============================================
-- TRIGGER UTAMA: Update status pembayaran dari Midtrans logs (FIXED)
-- ============================================
CREATE TRIGGER after_insert_midtrans_log
AFTER INSERT ON midtrans_logs
FOR EACH ROW
BEGIN
    DECLARE v_pesanan_id INT;
    DECLARE v_mobil_id INT;
    DECLARE v_user_id INT;
    
    -- Cari pesanan berdasarkan order_id
    SELECT id, mobil_id, user_id INTO v_pesanan_id, v_mobil_id, v_user_id
    FROM pesanan 
    WHERE kode_pesanan = NEW.order_id;
    
    IF v_pesanan_id IS NOT NULL THEN
        -- Update status berdasarkan transaction_status
        IF NEW.transaction_status IN ('settlement', 'capture') THEN
            -- Pembayaran BERHASIL
            UPDATE pesanan 
            SET status_pembayaran = 'paid',
                status = 'dikonfirmasi',
                midtrans_order_id = NEW.transaction_id,
                midtrans_transaction_status = NEW.transaction_status,
                payment_type = NEW.payment_type,
                bank = NEW.bank,
                va_number = NEW.va_number,
                transaction_time = NEW.created_at,
                settlement_time = CASE 
                    WHEN NEW.transaction_status = 'settlement' THEN NEW.created_at
                    ELSE NULL
                END,
                tanggal_pembayaran = NEW.created_at,
                updated_at = NOW()
            WHERE id = v_pesanan_id;
            
            -- Update status mobil menjadi DISEWA
            UPDATE mobil SET status = 'disewa', updated_at = NOW() 
            WHERE id = v_mobil_id;
            
            -- Insert ke tabel pembayaran JIKA belum ada
            INSERT INTO pembayaran (
                pesanan_id, 
                jumlah, 
                metode, 
                status, 
                transaction_id, 
                payment_type, 
                bank, 
                va_number, 
                tanggal_pembayaran,
                created_at,
                updated_at
            )
            SELECT 
                p.id,
                p.total_harga,
                'midtrans',
                CASE NEW.transaction_status 
                    WHEN 'settlement' THEN 'success'
                    WHEN 'capture' THEN 'capture'
                    ELSE 'pending'
                END,
                NEW.transaction_id,
                NEW.payment_type,
                NEW.bank,
                NEW.va_number,
                NEW.created_at,
                NOW(),
                NOW()
            FROM pesanan p
            WHERE p.id = v_pesanan_id
            AND NOT EXISTS (
                SELECT 1 FROM pembayaran pb 
                WHERE pb.pesanan_id = p.id 
                AND pb.transaction_id = NEW.transaction_id
            );
            
        ELSEIF NEW.transaction_status = 'pending' THEN
            -- Pembayaran PENDING
            UPDATE pesanan 
            SET status_pembayaran = 'pending',
                midtrans_order_id = NEW.transaction_id,
                midtrans_transaction_status = NEW.transaction_status,
                payment_type = NEW.payment_type,
                bank = NEW.bank,
                va_number = NEW.va_number,
                updated_at = NOW()
            WHERE id = v_pesanan_id;
            
        ELSEIF NEW.transaction_status IN ('deny', 'cancel', 'expire', 'failure') THEN
            -- Pembayaran GAGAL
            UPDATE pesanan 
            SET status_pembayaran = 'failed',
                status = 'dibatalkan',
                midtrans_order_id = NEW.transaction_id,
                midtrans_transaction_status = NEW.transaction_status,
                updated_at = NOW()
            WHERE id = v_pesanan_id;
            
            -- Kembalikan status mobil menjadi TERSEDIA
            UPDATE mobil SET status = 'tersedia', updated_at = NOW() 
            WHERE id = v_mobil_id;
        END IF;
    END IF;
END //

DELIMITER ;

-- ============================================
-- STORED PROCEDURES (DIPERBAIKI)
-- ============================================

DELIMITER //

-- Procedure untuk mendapatkan statistik harian dengan Midtrans
CREATE PROCEDURE GetDailyStats(IN p_date DATE)
BEGIN
    SELECT 
        COUNT(DISTINCT p.id) as total_orders,
        COUNT(DISTINCT p.user_id) as total_customers,
        COALESCE(SUM(CASE WHEN p.status_pembayaran = 'paid' THEN p.total_harga ELSE 0 END), 0) as total_revenue,
        COUNT(DISTINCT CASE WHEN p.status_pembayaran = 'paid' THEN p.mobil_id END) as cars_rented,
        COUNT(DISTINCT CASE WHEN p.status_pembayaran = 'pending' THEN p.id END) as pending_payments,
        COUNT(DISTINCT CASE WHEN p.status_pembayaran = 'failed' THEN p.id END) as failed_payments
    FROM pesanan p
    WHERE DATE(p.tanggal_pemesanan) = p_date;
END //

-- Procedure untuk mendapatkan pendapatan bulanan dengan detail Midtrans
CREATE PROCEDURE GetMonthlyRevenue(IN p_year INT, IN p_month INT)
BEGIN
    SELECT 
        DAY(tanggal_pemesanan) as day,
        COUNT(*) as order_count,
        COALESCE(SUM(CASE WHEN status_pembayaran = 'paid' THEN total_harga ELSE 0 END), 0) as daily_revenue,
        COUNT(CASE WHEN status_pembayaran = 'paid' THEN 1 END) as successful_payments,
        COUNT(CASE WHEN status_pembayaran = 'pending' THEN 1 END) as pending_payments,
        COUNT(CASE WHEN status_pembayaran = 'failed' THEN 1 END) as failed_payments
    FROM pesanan 
    WHERE YEAR(tanggal_pemesanan) = p_year
    AND MONTH(tanggal_pemesanan) = p_month
    GROUP BY DAY(tanggal_pemesanan)
    ORDER BY day;
END //

-- Procedure untuk update status mobil otomatis
CREATE PROCEDURE UpdateCarStatus()
BEGIN
    -- Update mobil yang sudah selesai disewa
    UPDATE mobil m
    JOIN pesanan p ON m.id = p.mobil_id
    SET m.status = 'tersedia',
        m.updated_at = NOW()
    WHERE p.status = 'selesai'
    AND p.tanggal_selesai < CURDATE();
    
    -- Update pesanan yang sudah lewat tanggal selesai
    UPDATE pesanan
    SET status = 'selesai',
        updated_at = NOW()
    WHERE status = 'dikonfirmasi'
    AND tanggal_selesai < CURDATE();
    
    -- Update status pembayaran yang expired (lebih dari 24 jam)
    UPDATE pesanan
    SET status_pembayaran = 'expired',
        status = 'dibatalkan',
        updated_at = NOW()
    WHERE status_pembayaran = 'pending'
    AND created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR);
    
    -- Update mobil untuk pesanan yang expired
    UPDATE mobil m
    JOIN pesanan p ON m.id = p.mobil_id
    SET m.status = 'tersedia',
        m.updated_at = NOW()
    WHERE p.status_pembayaran = 'expired'
    AND p.status = 'dibatalkan';
END //

-- Procedure untuk mendapatkan token Midtrans untuk pesanan
CREATE PROCEDURE GetMidtransToken(IN p_order_id VARCHAR(100))
BEGIN
    SELECT midtrans_token, status_pembayaran, total_harga, midtrans_order_id
    FROM pesanan 
    WHERE kode_pesanan = p_order_id;
END //

-- Procedure untuk update status pembayaran Midtrans (FIXED)
CREATE PROCEDURE UpdateMidtransPayment(
    IN p_order_id VARCHAR(100),
    IN p_transaction_id VARCHAR(100),
    IN p_transaction_status VARCHAR(50),
    IN p_fraud_status VARCHAR(50),
    IN p_payment_type VARCHAR(50),
    IN p_bank VARCHAR(50),
    IN p_va_number VARCHAR(50),
    IN p_gross_amount DECIMAL(10,2),
    IN p_response_data JSON
)
BEGIN
    DECLARE v_payment_status VARCHAR(20);
    DECLARE v_order_status VARCHAR(20);
    DECLARE v_mobil_id INT;
    DECLARE v_pesanan_id INT;
    
    -- Determine payment status based on Midtrans response
    SET v_payment_status = CASE 
        WHEN p_transaction_status IN ('settlement', 'capture') THEN 'paid'
        WHEN p_transaction_status = 'pending' THEN 'pending'
        ELSE 'failed'
    END;
    
    SET v_order_status = CASE 
        WHEN p_transaction_status IN ('settlement', 'capture') THEN 'dikonfirmasi'
        WHEN p_transaction_status = 'pending' THEN 'pending'
        ELSE 'dibatalkan'
    END;
    
    -- Get mobil_id and pesanan_id
    SELECT id, mobil_id INTO v_pesanan_id, v_mobil_id 
    FROM pesanan 
    WHERE kode_pesanan = p_order_id;
    
    -- Update pesanan
    UPDATE pesanan 
    SET status_pembayaran = v_payment_status,
        status = v_order_status,
        midtrans_order_id = p_transaction_id,
        midtrans_transaction_status = p_transaction_status,
        payment_type = p_payment_type,
        bank = p_bank,
        va_number = p_va_number,
        transaction_time = NOW(),
        settlement_time = CASE 
            WHEN p_transaction_status = 'settlement' THEN NOW()
            ELSE NULL
        END,
        tanggal_pembayaran = CASE 
            WHEN p_transaction_status IN ('settlement', 'capture') THEN NOW()
            ELSE NULL
        END,
        updated_at = NOW()
    WHERE kode_pesanan = p_order_id;
    
    -- Insert into pembayaran table if successful
    IF p_transaction_status IN ('settlement', 'capture') THEN
        INSERT INTO pembayaran (pesanan_id, jumlah, metode, status, transaction_id, 
                               payment_type, bank, va_number, tanggal_pembayaran, created_at)
        SELECT id, total_harga, 'midtrans', 
               CASE p_transaction_status 
                   WHEN 'settlement' THEN 'success'
                   WHEN 'capture' THEN 'capture'
                   ELSE 'pending'
               END,
               p_transaction_id, p_payment_type, p_bank, p_va_number, NOW(), NOW()
        FROM pesanan 
        WHERE kode_pesanan = p_order_id
        AND NOT EXISTS (
            SELECT 1 FROM pembayaran pb 
            WHERE pb.pesanan_id = v_pesanan_id 
            AND pb.transaction_id = p_transaction_id
        );
        
        -- Update mobil status if payment successful
        UPDATE mobil SET status = 'disewa', updated_at = NOW() 
        WHERE id = v_mobil_id;
        
    ELSEIF p_transaction_status IN ('deny', 'cancel', 'expire', 'failure') THEN
        -- Update mobil status if payment failed
        UPDATE mobil SET status = 'tersedia', updated_at = NOW() 
        WHERE id = v_mobil_id;
    END IF;
    
    -- Insert into midtrans_logs
    INSERT INTO midtrans_logs (order_id, transaction_id, transaction_status, fraud_status, 
                              payment_type, bank, va_number, gross_amount, response_data)
    VALUES (p_order_id, p_transaction_id, p_transaction_status, p_fraud_status, 
            p_payment_type, p_bank, p_va_number, p_gross_amount, p_response_data);
    
    -- Return success
    SELECT 'Payment status updated successfully' as message;
END //

-- Procedure untuk mendapatkan laporan transaksi Midtrans
CREATE PROCEDURE GetMidtransReport(IN p_start_date DATE, IN p_end_date DATE)
BEGIN
    SELECT 
        p.kode_pesanan,
        p.tanggal_pemesanan,
        u.nama as customer_name,
        u.email,
        m.merk,
        m.model,
        p.total_harga,
        p.status_pembayaran,
        p.payment_type,
        p.bank,
        p.va_number,
        p.midtrans_order_id,
        p.transaction_time,
        p.settlement_time,
        ml.transaction_status,
        ml.fraud_status
    FROM pesanan p
    JOIN users u ON p.user_id = u.id
    JOIN mobil m ON p.mobil_id = m.id
    LEFT JOIN midtrans_logs ml ON p.kode_pesanan = ml.order_id
    WHERE DATE(p.tanggal_pemesanan) BETWEEN p_start_date AND p_end_date
    AND p.metode_pembayaran = 'midtrans'
    ORDER BY p.tanggal_pemesanan DESC;
END //

-- Procedure untuk force update payment status (untuk manual fix)
CREATE PROCEDURE ForceUpdatePaymentStatus(
    IN p_order_id VARCHAR(100),
    IN p_new_status ENUM('paid', 'pending', 'failed')
)
BEGIN
    DECLARE v_mobil_id INT;
    DECLARE v_pesanan_id INT;
    
    -- Get mobil_id and pesanan_id
    SELECT id, mobil_id INTO v_pesanan_id, v_mobil_id 
    FROM pesanan 
    WHERE kode_pesanan = p_order_id;
    
    -- Update payment status
    UPDATE pesanan 
    SET status_pembayaran = p_new_status,
        status = CASE 
            WHEN p_new_status = 'paid' THEN 'dikonfirmasi'
            WHEN p_new_status = 'failed' THEN 'dibatalkan'
            ELSE status
        END,
        tanggal_pembayaran = CASE 
            WHEN p_new_status = 'paid' THEN NOW()
            ELSE NULL
        END,
        updated_at = NOW()
    WHERE kode_pesanan = p_order_id;
    
    -- Update mobil status
    IF p_new_status = 'paid' THEN
        UPDATE mobil SET status = 'disewa', updated_at = NOW() WHERE id = v_mobil_id;
    ELSEIF p_new_status = 'failed' THEN
        UPDATE mobil SET status = 'tersedia', updated_at = NOW() WHERE id = v_mobil_id;
    END IF;
    
    -- Insert payment record if paid
    IF p_new_status = 'paid' THEN
        INSERT INTO pembayaran (pesanan_id, jumlah, metode, status, tanggal_pembayaran, created_at)
        SELECT id, total_harga, 'midtrans', 'success', NOW(), NOW()
        FROM pesanan 
        WHERE kode_pesanan = p_order_id
        AND NOT EXISTS (
            SELECT 1 FROM pembayaran pb 
            WHERE pb.pesanan_id = v_pesanan_id 
            AND pb.status = 'success'
        );
    END IF;
    
    SELECT CONCAT('Payment status updated to ', p_new_status) as message;
END //

DELIMITER ;

-- ============================================
-- VIEWS (DIPERBAIKI)
-- ============================================

-- View untuk melihat detail pesanan lengkap dengan Midtrans
CREATE OR REPLACE VIEW vw_order_details AS
SELECT 
    p.kode_pesanan,
    p.tanggal_pemesanan,
    p.tanggal_mulai,
    p.tanggal_selesai,
    p.durasi_hari,
    p.total_harga,
    p.status as order_status,
    p.status_pembayaran,
    p.metode_pembayaran,
    p.payment_type,
    p.bank,
    p.va_number,
    p.midtrans_token,
    p.midtrans_order_id,
    p.midtrans_transaction_status,
    p.transaction_time,
    p.settlement_time,
    p.tanggal_pembayaran,
    u.nama as customer_name,
    u.email as customer_email,
    u.no_telepon as customer_phone,
    m.merk as car_brand,
    m.model as car_model,
    m.plat_nomor as car_plate,
    m.tipe as car_type,
    m.harga_per_hari as daily_rate,
    m.status as car_status
FROM pesanan p
JOIN users u ON p.user_id = u.id
JOIN mobil m ON p.mobil_id = m.id;

-- View untuk melihat chat antara user
CREATE OR REPLACE VIEW vw_chat_messages AS
SELECT 
    c.id,
    c.sender_id,
    s.nama as sender_name,
    s.foto_profil as sender_photo,
    c.receiver_id,
    r.nama as receiver_name,
    r.foto_profil as receiver_photo,
    c.message,
    c.is_read,
    c.created_at
FROM chat c
JOIN users s ON c.sender_id = s.id
JOIN users r ON c.receiver_id = r.id;

-- View untuk melihat transaksi Midtrans
CREATE OR REPLACE VIEW vw_midtrans_transactions AS
SELECT 
    p.kode_pesanan,
    p.tanggal_pemesanan,
    p.tanggal_pembayaran,
    u.nama as customer_name,
    m.merk as car_brand,
    m.model as car_model,
    p.total_harga,
    p.status_pembayaran,
    p.payment_type,
    p.bank,
    p.va_number,
    p.midtrans_order_id,
    p.midtrans_transaction_status,
    ml.transaction_status,
    ml.fraud_status,
    ml.created_at as notification_time
FROM pesanan p
JOIN users u ON p.user_id = u.id
JOIN mobil m ON p.mobil_id = m.id
LEFT JOIN midtrans_logs ml ON p.kode_pesanan = ml.order_id
WHERE p.metode_pembayaran = 'midtrans'
ORDER BY p.tanggal_pemesanan DESC;

-- View untuk melihat pembayaran yang sudah lunas
CREATE OR REPLACE VIEW vw_successful_payments AS
SELECT 
    p.kode_pesanan,
    p.tanggal_pemesanan,
    p.tanggal_pembayaran,
    p.total_harga,
    u.nama as customer_name,
    u.email as customer_email,
    m.merk as car_brand,
    m.model as car_model,
    m.gambar as car_image,
    pb.status as payment_status,
    pb.transaction_id,
    pb.payment_type,
    pb.bank
FROM pesanan p
JOIN users u ON p.user_id = u.id
JOIN mobil m ON p.mobil_id = m.id
LEFT JOIN pembayaran pb ON p.id = pb.pesanan_id AND pb.status = 'success'
WHERE p.status_pembayaran = 'paid'
ORDER BY p.tanggal_pembayaran DESC;

-- ============================================
-- CREATE INDEXES TAMBAHAN untuk performa
-- ============================================

CREATE INDEX idx_users_created ON users(created_at);
CREATE INDEX idx_users_last_login ON users(last_login);
CREATE INDEX idx_mobil_created ON mobil(created_at);
CREATE INDEX idx_mobil_harga ON mobil(harga_per_hari);
CREATE INDEX idx_pesanan_dates ON pesanan(tanggal_mulai, tanggal_selesai);
CREATE INDEX idx_pesanan_midtrans ON pesanan(midtrans_token, midtrans_order_id);
CREATE INDEX idx_pesanan_payment_status ON pesanan(status_pembayaran, status);
CREATE INDEX idx_pesanan_user_date ON pesanan(user_id, tanggal_pemesanan);
CREATE INDEX idx_pembayaran_transaction ON pembayaran(transaction_id, status);
CREATE INDEX idx_pembayaran_date ON pembayaran(tanggal_pembayaran);
CREATE INDEX idx_midtrans_order_status ON midtrans_logs(order_id, transaction_status);
CREATE INDEX idx_midtrans_created ON midtrans_logs(created_at);
CREATE INDEX idx_chat_conversation ON chat(sender_id, receiver_id, created_at);
CREATE INDEX idx_chat_read_status ON chat(is_read, receiver_id);

-- ============================================
-- EVENT SCHEDULER untuk maintenance otomatis
-- ============================================

-- Aktifkan event scheduler
SET GLOBAL event_scheduler = ON;

-- Event untuk update status harian
DELIMITER //
CREATE EVENT IF NOT EXISTS daily_status_update
ON SCHEDULE EVERY 1 DAY
STARTS TIMESTAMP(CURRENT_DATE, '00:05:00')
DO
BEGIN
    -- Panggil procedure update status
    CALL UpdateCarStatus();
    
    -- Clean old midtrans logs (keep 30 days)
    DELETE FROM midtrans_logs 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
    
    -- Update payment status yang pending lebih dari 1 jam
    UPDATE pesanan p
    JOIN midtrans_logs ml ON p.kode_pesanan = ml.order_id
    SET p.status_pembayaran = 'failed',
        p.status = 'dibatalkan',
        p.updated_at = NOW()
    WHERE p.status_pembayaran = 'pending'
    AND ml.transaction_status IN ('expire', 'failure', 'deny', 'cancel')
    AND ml.created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);
END //

DELIMITER ;

-- ============================================
-- FUNCTION UTILITY (TAMBAHAN)
-- ============================================

DELIMITER //

-- Function untuk generate kode pesanan
CREATE FUNCTION GenerateOrderCode() RETURNS VARCHAR(20)
BEGIN
    DECLARE new_code VARCHAR(20);
    SET new_code = CONCAT('RENT-', DATE_FORMAT(NOW(), '%Y%m%d'), '-', 
                         UPPER(SUBSTRING(MD5(RAND()), 1, 6)));
    RETURN new_code;
END //

-- Function untuk cek ketersediaan mobil
CREATE FUNCTION CheckCarAvailability(
    p_mobil_id INT,
    p_start_date DATE,
    p_end_date DATE
) RETURNS BOOLEAN
BEGIN
    DECLARE is_available BOOLEAN;
    
    SELECT COUNT(*) = 0 INTO is_available
    FROM pesanan p
    WHERE p.mobil_id = p_mobil_id
    AND p.status NOT IN ('dibatalkan', 'selesai')
    AND p.status_pembayaran = 'paid'
    AND (
        (p.tanggal_mulai BETWEEN p_start_date AND p_end_date) OR
        (p.tanggal_selesai BETWEEN p_start_date AND p_end_date) OR
        (p_start_date BETWEEN p.tanggal_mulai AND p.tanggal_selesai) OR
        (p_end_date BETWEEN p.tanggal_mulai AND p.tanggal_selesai)
    );
    
    RETURN is_available;
END //

-- Function untuk mendapatkan total pendapatan user
CREATE FUNCTION GetUserTotalSpent(p_user_id INT) RETURNS DECIMAL(12,2)
BEGIN
    DECLARE total DECIMAL(12,2);
    
    SELECT COALESCE(SUM(total_harga), 0) INTO total
    FROM pesanan
    WHERE user_id = p_user_id
    AND status_pembayaran = 'paid';
    
    RETURN total;
END //

-- Function untuk cek status pembayaran pesanan
CREATE FUNCTION CheckOrderPaymentStatus(p_order_code VARCHAR(20)) 
RETURNS VARCHAR(20)
BEGIN
    DECLARE payment_status VARCHAR(20);
    
    SELECT status_pembayaran INTO payment_status
    FROM pesanan
    WHERE kode_pesanan = p_order_code;
    
    RETURN IFNULL(payment_status, 'not_found');
END //

DELIMITER ;

-- ============================================
-- TEST DATA untuk Midtrans (DIPERBAIKI)
-- ============================================

-- Update sample orders dengan tanggal pembayaran
UPDATE pesanan 
SET tanggal_pembayaran = NOW() - INTERVAL 2 DAY,
    midtrans_order_id = 'MIDTRANS-TEST-001',
    payment_type = 'credit_card',
    bank = 'bca',
    transaction_time = NOW() - INTERVAL 2 DAY,
    settlement_time = NOW() - INTERVAL 2 DAY
WHERE kode_pesanan = 'RENT-20240101-ABC123';

-- Insert test Midtrans logs
INSERT INTO midtrans_logs (order_id, transaction_id, transaction_status, fraud_status, payment_type, bank, va_number, gross_amount, response_data) 
VALUES 
('RENT-20240101-ABC123', 'MIDTRANS-TEST-001', 'settlement', 'accept', 'credit_card', 'bca', NULL, 1400000, '{"status": "success", "settlement_time": "' || DATE_FORMAT(NOW() - INTERVAL 2 DAY, '%Y-%m-%d %H:%i:%s') || '"}'),
('RENT-20240102-DEF456', 'MIDTRANS-TEST-002', 'pending', NULL, 'bank_transfer', 'bni', '98877665544332211', 3000000, '{"status": "pending"}'),
('RENT-20240103-GHI789', 'MIDTRANS-TEST-003', 'expire', NULL, 'credit_card', 'mandiri', NULL, 900000, '{"status": "expired"}');

-- Insert test pembayaran records
INSERT INTO pembayaran (pesanan_id, jumlah, metode, status, transaction_id, payment_type, bank, tanggal_pembayaran, created_at)
SELECT p.id, p.total_harga, 'midtrans', 'success', 'MIDTRANS-TEST-001', 'credit_card', 'bca', p.tanggal_pembayaran, NOW()
FROM pesanan p WHERE p.kode_pesanan = 'RENT-20240101-ABC123'
ON DUPLICATE KEY UPDATE updated_at = NOW();

INSERT INTO pembayaran (pesanan_id, jumlah, metode, status, transaction_id, payment_type, bank, tanggal_pembayaran, created_at)
SELECT p.id, p.total_harga, 'midtrans', 'pending', 'MIDTRANS-TEST-002', 'bank_transfer', 'bni', NULL, NOW()
FROM pesanan p WHERE p.kode_pesanan = 'RENT-20240102-DEF456'
ON DUPLICATE KEY UPDATE updated_at = NOW();

-- ============================================
-- QUERY TEST untuk verifikasi
-- ============================================

-- Test semua tabel
SELECT 'Testing Users Table' as test;
SELECT COUNT(*) as total_users, 
       SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_count,
       SUM(CASE WHEN role = 'customer' THEN 1 ELSE 0 END) as customer_count,
       SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_users
FROM users;

SELECT 'Testing Mobil Table' as test;
SELECT COUNT(*) as total_cars,
       SUM(CASE WHEN status = 'tersedia' THEN 1 ELSE 0 END) as available_cars,
       SUM(CASE WHEN status = 'disewa' THEN 1 ELSE 0 END) as rented_cars,
       SUM(CASE WHEN status = 'maintenance' THEN 1 ELSE 0 END) as maintenance_cars
FROM mobil;

SELECT 'Testing Pesanan Table' as test;
SELECT COUNT(*) as total_orders,
       SUM(CASE WHEN status_pembayaran = 'paid' THEN 1 ELSE 0 END) as paid_orders,
       SUM(CASE WHEN status_pembayaran = 'pending' THEN 1 ELSE 0 END) as pending_orders,
       SUM(CASE WHEN status_pembayaran = 'failed' THEN 1 ELSE 0 END) as failed_orders,
       SUM(CASE WHEN metode_pembayaran = 'midtrans' THEN 1 ELSE 0 END) as midtrans_orders
FROM pesanan;

SELECT 'Testing Pembayaran Table' as test;
SELECT COUNT(*) as total_payments,
       SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success_payments,
       SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_payments,
       SUM(CASE WHEN metode = 'midtrans' THEN 1 ELSE 0 END) as midtrans_payments
FROM pembayaran;

SELECT 'Testing Midtrans Integration' as test;
SELECT 
    p.kode_pesanan, 
    p.status_pembayaran, 
    p.midtrans_order_id, 
    p.midtrans_transaction_status,
    p.payment_type, 
    p.bank,
    p.tanggal_pembayaran,
    ml.transaction_status as midtrans_status
FROM pesanan p
LEFT JOIN midtrans_logs ml ON p.kode_pesanan = ml.order_id
WHERE p.metode_pembayaran = 'midtrans'
ORDER BY p.tanggal_pemesanan DESC;

-- Test trigger dengan menambahkan midtrans log baru
SELECT 'Testing Trigger: Add new settlement log' as test;
INSERT INTO midtrans_logs (order_id, transaction_id, transaction_status, fraud_status, payment_type, bank, gross_amount, response_data) 
VALUES ('RENT-20240102-DEF456', 'MIDTRANS-TEST-004', 'settlement', 'accept', 'bank_transfer', 'bni', 3000000, '{"status": "settlement"}');

-- Verifikasi status berubah
SELECT 'Verify Trigger Result' as test;
SELECT 
    p.kode_pesanan,
    p.status_pembayaran,
    p.status,
    p.tanggal_pembayaran,
    m.status as car_status
FROM pesanan p
JOIN mobil m ON p.mobil_id = m.id
WHERE p.kode_pesanan = 'RENT-20240102-DEF456';

-- Test function
SELECT 'Testing Functions' as test;
SELECT 
    GenerateOrderCode() as new_order_code,
    CheckCarAvailability(1, CURDATE(), DATE_ADD(CURDATE(), INTERVAL 3 DAY)) as car_1_available,
    GetUserTotalSpent(2) as user_2_total_spent,
    CheckOrderPaymentStatus('RENT-20240101-ABC123') as order_payment_status;

-- ============================================
-- USER PERMISSIONS untuk aplikasi
-- ============================================

-- Buat user khusus aplikasi (uncomment jika diperlukan)
/*
CREATE USER IF NOT EXISTS 'rental_app'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON rental_mobil.* TO 'rental_app'@'localhost';
FLUSH PRIVILEGES;
*/

-- ============================================
-- CLEANUP: Hapus test log yang dibuat
-- ============================================

DELETE FROM midtrans_logs WHERE order_id = 'RENT-20240102-DEF456' AND transaction_id = 'MIDTRANS-TEST-004';

-- Reset status untuk testing
UPDATE pesanan 
SET status_pembayaran = 'pending',
    status = 'pending',
    tanggal_pembayaran = NULL,
    midtrans_order_id = 'MIDTRANS-TEST-002',
    midtrans_transaction_status = 'pending'
WHERE kode_pesanan = 'RENT-20240102-DEF456';

UPDATE mobil SET status = 'tersedia' WHERE id = 3;

-- ============================================
-- INSTRUKSI PENGGUNAAN
-- ============================================

SELECT '=============================' as instruction;
SELECT 'DATABASE BERHASIL DIBUAT!' as instruction;
SELECT '=============================' as instruction;
SELECT '' as instruction;
SELECT 'INSTRUKSI PENGGUNAAN:' as instruction;
SELECT '1. Default Admin Login:' as instruction;
SELECT '   Email: admin@rental.com' as instruction;
SELECT '   Password: admin123' as instruction;
SELECT '' as instruction;
SELECT '2. Default Customer Login:' as instruction;
SELECT '   Email: customer@demo.com' as instruction;
SELECT '   Password: customer123' as instruction;
SELECT '' as instruction;
SELECT '3. Midtrans Testing:' as instruction;
SELECT '   Mode: Sandbox' as instruction;
SELECT '   Webhook URL: http://your-domain/payment/notification' as instruction;
SELECT '   Test Card: 4811 1111 1111 1114' as instruction;
SELECT '' as instruction;
SELECT '4. Untuk testing payment status:' as instruction;
SELECT '   CALL UpdateMidtransPayment(''RENT-20240102-DEF456'', ''TEST-123'', ''settlement'', ''accept'', ''credit_card'', ''bca'', NULL, 3000000, ''{}'');' as instruction;
SELECT '' as instruction;
SELECT '5. Untuk force update status:' as instruction;
SELECT '   CALL ForceUpdatePaymentStatus(''RENT-20240102-DEF456'', ''paid'');' as instruction;

-- ============================================
-- SELESAI
-- ============================================

SELECT NOW() as Created_At;
SELECT 'Database rental_mobil berhasil dibuat dengan integrasi Midtrans yang telah diperbaiki!' as Status;