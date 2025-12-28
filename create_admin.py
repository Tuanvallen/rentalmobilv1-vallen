"""
CREATE ADMIN USER - REVISI
Script untuk membuat user admin baru dengan password yang benar
"""

import bcrypt
import mysql.connector
import sys

# Konfigurasi database - SESUAIKAN DENGAN SETTING ANDA
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Kosongkan jika tidak ada password
    'database': 'rental_mobil'
}

def create_admin(email, password, nama="Admin Rental", nik="9999999999999999"):
    """Buat admin baru dengan hash yang kompatibel"""
    try:
        # Hash password menggunakan bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Konversi ke string (Python bcrypt menghasilkan bytes)
        hashed_password_str = hashed_password.decode('utf-8')
        
        print("=" * 60)
        print("MENCIPTAKAN ADMIN BARU")
        print("=" * 60)
        print(f"Email: {email}")
        print(f"Password: {password}")
        print(f"Nama: {nama}")
        print(f"NIK: {nik}")
        print(f"Hash Password: {hashed_password_str[:50]}...")
        print("-" * 60)
        
        # Koneksi database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Cek apakah email sudah ada
        cursor.execute("SELECT id, nama, email FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            print(f"⚠️ PERINGATAN: Email {email} sudah terdaftar!")
            print(f"   ID: {existing_user[0]}")
            print(f"   Nama: {existing_user[1]}")
            print(f"   Email: {existing_user[2]}")
            
            # Tanya apakah ingin update password
            response = input("Apakah Anda ingin mengupdate password untuk user ini? (y/n): ")
            if response.lower() == 'y':
                cursor.execute("UPDATE users SET password = %s WHERE email = %s", 
                             (hashed_password_str, email))
                conn.commit()
                print("✅ Password berhasil diupdate!")
            else:
                print("❌ Operasi dibatalkan")
                return False
        else:
            # Insert admin baru
            cursor.execute("""
                INSERT INTO users (nama, email, password, nik, no_telepon, alamat, 
                                 tanggal_lahir, role, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (nama, email, hashed_password_str, nik, '081234567890', 
                  'Jl. Admin No. 1', '1990-01-01', 'admin', 'active'))
            
            conn.commit()
            admin_id = cursor.lastrowid
            print("✅ Admin baru berhasil dibuat!")
            print(f"   ID Admin: {admin_id}")
        
        # Verifikasi login
        print("\n" + "=" * 60)
        print("VERIFIKASI LOGIN")
        print("=" * 60)
        
        # Test login dengan password yang sama
        test_password = input("Masukkan password untuk verifikasi: ").strip()
        
        cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
        db_hash = cursor.fetchone()[0]
        
        # Verifikasi password
        if db_hash.startswith('$2y$'):
            db_hash = '$2b$' + db_hash[4:]
        
        is_valid = bcrypt.checkpw(test_password.encode('utf-8'), db_hash.encode('utf-8'))
        
        if is_valid:
            print("✅ VERIFIKASI BERHASIL: Password cocok dengan database!")
        else:
            print("❌ VERIFIKASI GAGAL: Password tidak cocok!")
            print("   Hash di DB:", db_hash[:50] + "...")
        
        cursor.close()
        conn.close()
        
        print("\n" + "=" * 60)
        print("INSTRUKSI LOGIN")
        print("=" * 60)
        print("1. Jalankan Flask app: python app.py")
        print("2. Buka browser: http://localhost:5000")
        print("3. Login dengan:")
        print(f"   Email: {email}")
        print(f"   Password: {password}")
        print("=" * 60)
        
        return True
        
    except mysql.connector.Error as err:
        print(f"❌ ERROR DATABASE: {err}")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def reset_admin_password(email, new_password):
    """Reset password untuk admin yang ada"""
    try:
        # Hash password baru
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        hashed_password_str = hashed_password.decode('utf-8')
        
        print("=" * 60)
        print("RESET PASSWORD ADMIN")
        print("=" * 60)
        
        # Koneksi database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Cek apakah email ada
        cursor.execute("SELECT id, nama FROM users WHERE email = %s AND role = 'admin'", (email,))
        admin = cursor.fetchone()
        
        if not admin:
            print(f"❌ Admin dengan email {email} tidak ditemukan!")
            cursor.close()
            conn.close()
            return False
        
        print(f"Admin ditemukan:")
        print(f"   ID: {admin[0]}")
        print(f"   Nama: {admin[1]}")
        print(f"   Email: {email}")
        print(f"   Password baru: {new_password}")
        print("-" * 60)
        
        # Update password
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", 
                      (hashed_password_str, email))
        conn.commit()
        
        print("✅ Password admin berhasil direset!")
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def list_all_admins():
    """Tampilkan semua admin di database"""
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, nama, email, nik, status, created_at 
            FROM users 
            WHERE role = 'admin' 
            ORDER BY created_at DESC
        """)
        
        admins = cursor.fetchall()
        
        print("=" * 60)
        print("DAFTAR SEMUA ADMIN")
        print("=" * 60)
        
        if not admins:
            print("❌ Tidak ada admin yang terdaftar")
        else:
            for i, admin in enumerate(admins, 1):
                print(f"\n{i}. ID: {admin['id']}")
                print(f"   Nama: {admin['nama']}")
                print(f"   Email: {admin['email']}")
                print(f"   NIK: {admin['nik']}")
                print(f"   Status: {admin['status']}")
                print(f"   Dibuat: {admin['created_at']}")
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def main_menu():
    """Menu utama"""
    while True:
        print("\n" + "=" * 60)
        print("MANAJEMEN ADMIN - RENTAL MOBIL")
        print("=" * 60)
        print("1. Buat Admin Baru")
        print("2. Reset Password Admin")
        print("3. Lihat Semua Admin")
        print("4. Test Koneksi Database")
        print("5. Keluar")
        print("=" * 60)
        
        choice = input("Pilihan Anda (1-5): ").strip()
        
        if choice == '1':
            print("\n--- BUAT ADMIN BARU ---")
            email = input("Email admin: ").strip()
            password = input("Password: ").strip()
            confirm = input("Konfirmasi password: ").strip()
            
            if password != confirm:
                print("❌ Password tidak cocok!")
                continue
            
            nama = input("Nama admin [Admin Rental]: ").strip()
            if not nama:
                nama = "Admin Rental"
            
            nik = input("NIK [9999999999999999]: ").strip()
            if not nik:
                nik = "9999999999999999"
            
            create_admin(email, password, nama, nik)
            
        elif choice == '2':
            print("\n--- RESET PASSWORD ADMIN ---")
            list_all_admins()
            email = input("\nEmail admin yang ingin direset: ").strip()
            new_password = input("Password baru: ").strip()
            confirm = input("Konfirmasi password baru: ").strip()
            
            if new_password != confirm:
                print("❌ Password tidak cocok!")
                continue
            
            reset_admin_password(email, new_password)
            
        elif choice == '3':
            list_all_admins()
            
        elif choice == '4':
            test_database_connection()
            
        elif choice == '5':
            print("👋 Terima kasih! Program dihentikan.")
            break
            
        else:
            print("❌ Pilihan tidak valid!")

def test_database_connection():
    """Test koneksi ke database"""
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        print("=" * 60)
        print("TEST KONEKSI DATABASE")
        print("=" * 60)
        
        # Test query sederhana
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()[0]
        print(f"✅ MySQL Version: {version}")
        
        cursor.execute("SELECT DATABASE()")
        db_name = cursor.fetchone()[0]
        print(f"✅ Database: {db_name}")
        
        # Cek tabel users
        cursor.execute("""
            SELECT COUNT(*) as total_users,
                   COUNT(CASE WHEN role = 'admin' THEN 1 END) as admin_count,
                   COUNT(CASE WHEN role = 'customer' THEN 1 END) as customer_count
            FROM users
        """)
        stats = cursor.fetchone()
        print(f"✅ Total Users: {stats[0]}")
        print(f"✅ Admin Count: {stats[1]}")
        print(f"✅ Customer Count: {stats[2]}")
        
        cursor.close()
        conn.close()
        
        print("✅ Koneksi database BERHASIL!")
        
    except mysql.connector.Error as err:
        print(f"❌ ERROR KONEKSI DATABASE: {err}")
        print("\nPERIKSA KONFIGURASI:")
        print(f"  Host: {db_config['host']}")
        print(f"  User: {db_config['user']}")
        print(f"  Database: {db_config['database']}")
        
        # Tanya apakah ingin mengubah konfigurasi
        change = input("\nApakah ingin mengubah konfigurasi database? (y/n): ")
        if change.lower() == 'y':
            db_config['host'] = input(f"Host [{db_config['host']}]: ") or db_config['host']
            db_config['user'] = input(f"User [{db_config['user']}]: ") or db_config['user']
            db_config['password'] = input(f"Password: ") or db_config['password']
            db_config['database'] = input(f"Database [{db_config['database']}]: ") or db_config['database']
            print("✅ Konfigurasi diperbarui!")
            
if __name__ == "__main__":
    print("=" * 60)
    print("ADMIN MANAGEMENT TOOL - RENTAL MOBIL FLASK")
    print("=" * 60)
    
    # Tampilkan versi Python dan bcrypt
    print(f"Python: {sys.version}")
    print(f"bcrypt tersedia: {'✓' if 'bcrypt' in sys.modules else '✗'}")
    
    main_menu()