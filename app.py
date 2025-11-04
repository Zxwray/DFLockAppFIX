from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import os
import base64
import io
import rsa
import hashlib
import bcrypt
import hmac
import secrets
import numpy as np
from PIL import Image, ImageFilter


class Config:
    SECRET_KEY = 'your-secret-key-here-change-in-production'
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_DB = 'crypto_app'
    MYSQL_CURSORCLASS = 'DictCursor'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Buat folder uploads jika belum ada
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(os.path.join(UPLOAD_FOLDER, 'images'))
        os.makedirs(os.path.join(UPLOAD_FOLDER, 'files'))

app = Flask(__name__)
app.config.from_object(Config)

# Inisialisasi MySQL
mysql = MySQL(app)

# Algoritma Kriptografi Klasik
class CaesarCipher:
    @staticmethod
    def encrypt(text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result

    @staticmethod
    def decrypt(text, shift):
        return CaesarCipher.encrypt(text, -shift)

class VigenereCipher:
    @staticmethod
    def encrypt(text, key):
        result = ""
        key = key.upper()
        key_index = 0
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                key_char = key[key_index % len(key)]
                key_shift = ord(key_char) - ord('A')
                result += chr((ord(char) - ascii_offset + key_shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result

    @staticmethod
    def decrypt(text, key):
        result = ""
        key = key.upper()
        key_index = 0
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                key_char = key[key_index % len(key)]
                key_shift = ord(key_char) - ord('A')
                result += chr((ord(char) - ascii_offset - key_shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result

# Algoritma Kriptografi Modern
class AESCipher:
    def __init__(self, key=None):
        if key is None:
            key = get_random_bytes(32)
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = cipher.iv
        return base64.b64encode(iv + ct_bytes).decode()

    def decrypt(self, enc_data):
        enc_data = base64.b64decode(enc_data)
        iv = enc_data[:16]
        ct = enc_data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()

# File: app.py - Class steganography yang dioptimasi
class AdvancedSteganography:
    def __init__(self):
        self.methods = ['combined']
        self.lsb_delimiter = "###LSB_END###" # Tambahkan delimiter sebagai atribut kelas

    def encode_image(self, image_path, message, output_path, method='combined'):
        """Encode message dengan COMBINED method yang dioptimasi"""
        return self._encode_combined_optimized(image_path, message, output_path)

    def decode_image(self, image_path, method='combined'):
        """Decode message yang dioptimasi - CEPAT"""
        return self._decode_combined_fast(image_path)

    def _encode_combined_optimized(self, image_path, message, output_path):
        """COMBINED METHOD yang dioptimasi"""
        # Step 1: Encode dengan LSB Random (simpan seed di EOF)
        from PIL import Image
        import numpy as np
        import os # Import os
        
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        encoded = img.copy()
        width, height = img.size
        
        # Gunakan seed yang bisa diprediksi (hash dari message)
        seed = self._calculate_seed(message)
        np.random.seed(seed)
        
        message_with_delimiter = message + self.lsb_delimiter # Gunakan atribut kelas
        binary_message = ''.join([format(ord(i), '08b') for i in message_with_delimiter])
        
        # Generate random pixel sequence
        total_pixels = width * height
        pixel_indices = np.random.permutation(total_pixels)
        
        data_index = 0
        for idx in pixel_indices:
            if data_index >= len(binary_message):
                break
            
            y = idx // width
            x = idx % width
            
            pixel = list(img.getpixel((x, y)))
            
            # Encode Red channel
            if data_index < len(binary_message):
                pixel[0] = (pixel[0] & 0xFE) | int(binary_message[data_index])
                data_index += 1
            
            # Encode Green channel
            if data_index < len(binary_message):
                pixel[1] = (pixel[1] & 0xFE) | int(binary_message[data_index])
                data_index += 1
                
            encoded.putpixel((x, y), tuple(pixel))
        
        # Simpan gambar LSB dulu
        lsb_temp_path = output_path.replace('.', '_lsb.')
        encoded.save(lsb_temp_path)
        
        # Step 2: Tambahkan EOF layer dengan SEED information
        # Masukkan message_with_delimiter (yang sudah ada delimiter)
        self._add_eof_with_seed(lsb_temp_path, message_with_delimiter, seed, output_path) 
        
        # Hapus file temporary
        try:
            os.remove(lsb_temp_path)
        except:
            pass
        
        return True
    
    def _calculate_seed(self, message):
        """Hitung seed dari message (deterministic)"""
        # Gunakan hash sederhana yang konsisten
        return sum(ord(c) * (i + 1) for i, c in enumerate(message)) % 1000
    
    def _add_eof_with_seed(self, image_path, message_with_delimiter, seed, output_path):
        """EOF layer dengan informasi seed"""
        import os # Import os
        with open(image_path, 'rb') as f:
            lsb_data = f.read()
        
        # Simpan seed di EOF untuk mempermudah decode
        # Menggunakan message_with_delimiter karena ini adalah pesan yang disematkan
        eof_message = f"SEED:{seed}:MSG:{message_with_delimiter}::END_EOF"
        eof_bytes = eof_message.encode('utf-8')
        
        combined_data = lsb_data + eof_bytes
        
        with open(output_path, 'wb') as f:
            f.write(combined_data)
        
        return True
    
    def _decode_combined_fast(self, image_path):
        """Decode CEPAT - gunakan seed dari EOF"""
        result = ""
        
        # Step 1: Decode EOF layer dulu (cepat)
        eof_data = self._decode_eof_fast(image_path)
        if eof_data:
            seed = eof_data.get('seed')
            eof_message = eof_data.get('message', '')
            
            # *** MODIFIKASI INI: Hapus delimiter dari eof_message ***
            clean_eof_message = eof_message.replace(self.lsb_delimiter, "").strip()

            if clean_eof_message:
                # Tambahkan pesan EOF yang sudah bersih
                result += f"Pesan dari EOF: {clean_eof_message}\n" 
            
            # Step 2: Decode LSB dengan seed yang diketahui (cepat)
            if seed is not None:
                lsb_result = self._decode_lsb_with_seed(image_path, seed)
                if lsb_result:
                    result += f"Pesan dari LSB: {lsb_result}"
        
        return result.strip() if result else self._decode_fallback(image_path)
    
    def _decode_eof_fast(self, image_path):
        """Decode EOF layer dengan cepat"""
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
            
            # Cari EOF marker
            eof_marker = b"::END_EOF"
            if eof_marker in data:
                marker_pos = data.rfind(eof_marker)
                if marker_pos != -1:
                    # Extract data antara SEED: dan ::END_EOF
                    seed_start = data.rfind(b"SEED:", 0, marker_pos)
                    if seed_start != -1:
                        # Parse seed dan message
                        eof_content = data[seed_start:marker_pos].decode('utf-8', errors='ignore')
                        
                        # Extract seed
                        seed_match = eof_content.split('SEED:')[1].split(':MSG:')[0]
                        seed = int(seed_match) if seed_match.isdigit() else None
                        
                        # Extract message (ini masih mengandung ###LSB_END###)
                        msg_match = eof_content.split(':MSG:')[1] if ':MSG:' in eof_content else ""
                        
                        return {'seed': seed, 'message': msg_match}
        except Exception as e:
            # print(f"Fast EOF decode error: {e}")
            pass # Jangan tampilkan error di output akhir
        
        return None
    
    def _decode_lsb_with_seed(self, image_path, seed):
        """Decode LSL CEPAT dengan seed yang diketahui"""
        try:
            from PIL import Image
            import numpy as np
            
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            width, height = img.size
            
            # Gunakan seed yang diketahui (tidak perlu brute force)
            np.random.seed(seed)
            total_pixels = width * height
            pixel_indices = np.random.permutation(total_pixels)
            
            binary_data = ""
            for idx in pixel_indices:
                y = idx // width
                x = idx % width
                pixel = img.getpixel((x, y))
                
                # Kita hanya encode di R dan G, jadi hanya R dan G yang di-decode
                binary_data += str(pixel[0] & 1)  # Red channel
                binary_data += str(pixel[1] & 1)  # Green channel
            
            return self._binary_to_text_fast(binary_data, self.lsb_delimiter) # Gunakan atribut kelas
            
        except Exception as e:
            # print(f"LSB with seed decode error: {e}")
            pass # Jangan tampilkan error di output akhir
        
        return ""
    
    def _decode_fallback(self, image_path):
        """Fallback decoding jika metode cepat gagal"""
        result = ""
        
        # Coba EOF traditional
        eof_result = self._decode_eof_traditional(image_path)
        if eof_result:
            result += f"[EOF Fallback] {eof_result}\n"
        
        # Coba LSB dengan limited brute force (max 10 seed)
        for seed in range(10):  # Hanya coba 10 seed pertama
            lsb_result = self._decode_lsb_with_seed(image_path, seed)
            if lsb_result:
                result += f"[LSB Fallback] {lsb_result}"
                break
        
        return result.strip()
    
    def _decode_eof_traditional(self, image_path):
        """Traditional EOF decode"""
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
            
            # Cari berbagai possible markers
            markers = [b"###END###", b"::END_EOF", b"END_STEGO"]
            for marker in markers:
                if marker in data:
                    marker_pos = data.rfind(marker)
                    if marker_pos > len(data) - 1000:  # Pastikan di akhir file
                        # Ambil 1000 bytes sebelum marker sebagai message
                        start_pos = max(0, marker_pos - 1000)
                        message_data = data[start_pos:marker_pos]
                        
                        try:
                            decoded = message_data.decode('utf-8', errors='ignore')
                            # Hapus delimiter LSB dari hasil fallback
                            clean_decoded = decoded.replace(self.lsb_delimiter, "").strip() 
                            
                            # Cari text yang meaningful
                            if len(clean_decoded) > 5 and any(c.isalpha() for c in clean_decoded):
                                return clean_decoded[-100:]  # Return last 100 chars
                        except:
                            pass
        except:
            pass
        
        return ""
    
    def _binary_to_text_fast(self, binary_data, delimiter):
        """Convert binary to text yang dioptimasi"""
        # Batasi processing untuk performa
        max_bits = 100000  # Max 100k bits untuk hindari processing panjang
        if len(binary_data) > max_bits:
            binary_data = binary_data[:max_bits]
        
        all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        decoded_message = ""
        
        for byte in all_bytes:
            if len(byte) == 8:
                try:
                    char = chr(int(byte, 2))
                    decoded_message += char
                    if decoded_message.endswith(delimiter):
                        # Jika delimiter ditemukan, hapus dan kembalikan sisanya
                        return decoded_message[:-len(delimiter)]
                    # Batasi panjang message untuk performa
                    if len(decoded_message) > 1000:
                        break
                except:
                    continue
        
        return ""

# Inisialisasi advanced steganography
advanced_stego = AdvancedSteganography()

class DatabaseEncryption:
    def __init__(self, key=None):
        if key is None:
            # Generate key dari environment variable atau buat baru
            key = os.getenv('DB_ENCRYPTION_KEY', 'default-secret-key-32-chars-here!!')
        # Ensure key is 32 bytes for AES-256
        if len(key) < 32:
            key = key.ljust(32, '0')
        elif len(key) > 32:
            key = key[:32]
        self.key = key.encode()

    def encrypt(self, data):
        if data is None:
            return None
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        encrypted_data = cipher.nonce + tag + ciphertext
        return b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_data):
        if encrypted_data is None:
            return None
        try:
            encrypted_data = b64decode(encrypted_data)
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_data.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

# Inisialisasi database encryption
db_crypto = DatabaseEncryption()

class PasswordCrypto:
    def __init__(self):
        self.pepper = os.getenv('PEPPER_KEY', 'default-pepper-key-32-chars!!').encode()
    
    def hash_password_argon2(self, password):
        """Menggunakan Argon2id - hybrid version (recommended)"""
        try:
            from argon2 import PasswordHasher
            
            # Konfigurasi Argon2id
            ph = PasswordHasher(
                time_cost=3,       # 3 iterations
                memory_cost=65536, # 64MB memory
                parallelism=4,     # 4 parallel threads
                hash_len=32,       # 32 bytes hash length
                salt_len=16        # 16 bytes salt
            )
            
            # Tambahkan pepper sebelum hashing
            peppered_password = password.encode() + self.pepper
            return ph.hash(peppered_password)
            
        except ImportError:
            # Fallback ke bcrypt jika argon2 tidak tersedia
            print("Argon2 not available, falling back to bcrypt")
            return self.hash_password_bcrypt(password)
    
    def verify_password_argon2(self, password, stored_hash):
        """Verifikasi password dengan Argon2id"""
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            
            ph = PasswordHasher()
            peppered_password = password.encode() + self.pepper
            
            return ph.verify(stored_hash, peppered_password)
            
        except VerifyMismatchError:
            return False
        except ImportError:
            # Fallback verification
            return self.verify_password_bcrypt(password, stored_hash)
    
    def hash_password_bcrypt(self, password):
        """Fallback: bcrypt dengan pepper"""
        peppered_password = password.encode() + self.pepper
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(peppered_password, salt).decode()
    
    def verify_password_bcrypt(self, password, stored_hash):
        """Verifikasi bcrypt dengan pepper"""
        try:
            peppered_password = password.encode() + self.pepper
            return bcrypt.checkpw(peppered_password, stored_hash.encode())
        except:
            return False
    
    def verify_password(self, password, stored_hash):
        """Verifikasi password dengan semua algoritma yang didukung"""
        peppered_password = password.encode() + self.pepper
        
        # Coba Argon2id dulu
        try:
            if stored_hash.startswith('$argon2id$'):
                return self.verify_password_argon2(password, stored_hash)
        except:
            pass
        
        # Coba bcrypt
        if stored_hash.startswith('$2b$'):
            return self.verify_password_bcrypt(password, stored_hash)

# Inisialisasi password crypto
password_crypto = PasswordCrypto()


# Fungsi Super Enkripsi (Gabungan Klasik dan Modern)
def super_encrypt(text, caesar_shift, vigenere_key, aes_key=None):
    # Lapis 1: Caesar Cipher
    caesar_encrypted = CaesarCipher.encrypt(text, caesar_shift)
    
    # Lapis 2: Vigenere Cipher
    vigenere_encrypted = VigenereCipher.encrypt(caesar_encrypted, vigenere_key)
    
    # Lapis 3: AES
    if aes_key is None:
        aes_cipher = AESCipher()
    else:
        aes_cipher = AESCipher(aes_key)
    
    final_encrypted = aes_cipher.encrypt(vigenere_encrypted)
    
    return final_encrypted, aes_cipher.key

def super_decrypt(encrypted_text, caesar_shift, vigenere_key, aes_key):
    # Lapis 1: AES Decrypt
    aes_cipher = AESCipher(aes_key)
    aes_decrypted = aes_cipher.decrypt(encrypted_text)
    
    # Lapis 2: Vigenere Decrypt
    vigenere_decrypted = VigenereCipher.decrypt(aes_decrypted, vigenere_key)
    
    # Lapis 3: Caesar Decrypt
    caesar_decrypted = CaesarCipher.decrypt(vigenere_decrypted, caesar_shift)
    
    return caesar_decrypted

# Helper functions
def get_user_stats(user_id):
    cur = mysql.connection.cursor()
    
    # Hitung jumlah pesan terenkripsi
    cur.execute("SELECT COUNT(*) as count FROM encrypted_messages WHERE user_id = %s", (user_id,))
    message_count = cur.fetchone()['count']
    
    # Hitung jumlah file terenkripsi
    cur.execute("SELECT COUNT(*) as count FROM encrypted_files WHERE user_id = %s", (user_id,))
    file_count = cur.fetchone()['count']
    
    # Untuk gambar, kita asumsikan ada beberapa operasi (dalam implementasi nyata, buat tabel tersendiri)
    image_count = message_count + file_count
    
    total_operations = message_count + file_count + image_count
    
    cur.close()
    
    return {
        'message_count': message_count,
        'file_count': file_count,
        'image_count': image_count,
        'total_operations': total_operations
    }

def get_recent_activities(user_id):
    cur = mysql.connection.cursor()
    
    # Ambil aktivitas terbaru dari encrypted_messages
    cur.execute("""
        SELECT 'Enkripsi Teks' as type, algorithm_used as algorithm, created_at as timestamp 
        FROM encrypted_messages 
        WHERE user_id = %s 
        ORDER BY created_at DESC 
        LIMIT 3
    """, (user_id,))
    message_activities = cur.fetchall()
    
    # Ambil aktivitas terbaru dari encrypted_files
    cur.execute("""
        SELECT 'Enkripsi File' as type, algorithm_used as algorithm, created_at as timestamp 
        FROM encrypted_files 
        WHERE user_id = %s 
        ORDER BY created_at DESC 
        LIMIT 2
    """, (user_id,))
    file_activities = cur.fetchall()
    
    cur.close()
    
    # Gabungkan dan format aktivitas
    activities = []
    for activity in message_activities + file_activities:
        activities.append({
            'type': activity['type'],
            'description': f'{activity["type"]} dengan {activity["algorithm"]}',
            'timestamp': activity['timestamp'].strftime('%d/%m/%Y %H:%M'),
            'algorithm': activity['algorithm']
        })
    
    # Jika tidak ada aktivitas, berikan contoh
    if not activities:
        activities = [
            {
                'type': 'Enkripsi Teks',
                'description': 'Super encryption dengan Caesar + Vigenere + AES',
                'timestamp': 'Hari ini',
                'algorithm': 'Super Encryption'
            }
        ]
    
    return activities

def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Fungsi untuk log activity dengan enkripsi
def log_user_activity(user_id, activity_type, description, ip_address=None):
    try:
        cur = mysql.connection.cursor()
        
        # Enkripsi data activity
        activity_encrypted = db_crypto.encrypt(activity_type)
        description_encrypted = db_crypto.encrypt(description)
        ip_encrypted = db_crypto.encrypt(ip_address or request.remote_addr)
        
        cur.execute(
            "INSERT INTO user_activity_logs (user_id, activity_type_encrypted, description_encrypted, ip_address_encrypted) VALUES (%s, %s, %s, %s)",
            (user_id, activity_encrypted, description_encrypted, ip_encrypted)
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        print(f"Error logging activity: {e}")

# Tambahkan logging di setiap route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        
        if user and password_crypto.verify_password(password, user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            log_user_activity(user['id'], 'LOGIN', f'User {username} logged in')
            
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_user_activity(None, 'LOGIN_FAILED', f'Failed login for: {username}')
            flash('Username atau password salah!', 'danger')
    
    return render_template('login.html')

# Tambahkan fungsi untuk mengecek kekuatan password
def check_password_strength(password):
    """Check password strength with multiple criteria"""
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password terlalu pendek (minimal 8 karakter)")
    
    # Complexity checks
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Tambahkan huruf kecil")
        
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Tambahkan huruf besar")
        
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Tambahkan angka")
        
    if any(not c.isalnum() for c in password):
        score += 1
    else:
        feedback.append("Tambahkan karakter spesial")
    
    # Strength assessment
    if score >= 5:
        return "strong", feedback
    elif score >= 3:
        return "medium", feedback
    else:
        return "weak", feedback

# Update register function dengan strength check
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if len(password) < 8:
            flash('Password harus minimal 8 karakter!', 'danger')
            return render_template('register.html')
        
        # GUNAKAN ARGON2 + BCRYPT DENGAN PEPPER
        password_hash = password_crypto.hash_password_argon2(password)
        
        cur = mysql.connection.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, password_algorithm) VALUES (%s, %s, %s, %s)",
                (username, email, password_hash, 'argon2_bcrypt')
            )
            mysql.connection.commit()
            
            log_user_activity(cur.lastrowid, 'REGISTER', f'User {username} registered')
            
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            mysql.connection.rollback()
            flash('Username atau email sudah digunakan!', 'danger')
        finally:
            cur.close()
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    stats = get_user_stats(session['user_id'])
    recent_activities = get_recent_activities(session['user_id'])
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_activities=recent_activities)

@app.route('/text-encryption', methods=['GET', 'POST'])
def text_encryption():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text', '')
        caesar_shift = int(request.form.get('caesar_shift', 3))
        vigenere_key = request.form.get('vigenere_key', 'KEY')
        
        if not text:
            flash('Masukkan teks terlebih dahulu!', 'danger')
            return render_template('text_encryption.html')
        
        if action == 'encrypt':
            try:
                encrypted_text, aes_key = super_encrypt(text, caesar_shift, vigenere_key)
                result = {
                    'type': 'encrypted',
                    'original': text,
                    'result': encrypted_text,
                    'aes_key': base64.b64encode(aes_key).decode()
                }
                
                # SIMPAN KE DATABASE DENGAN ENKRIPSI
                cur = mysql.connection.cursor()
                
                # Enkripsi data sebelum disimpan
                original_encrypted = db_crypto.encrypt(text)
                encrypted_text_db = db_crypto.encrypt(encrypted_text)
                
                cur.execute(
                    "INSERT INTO encrypted_messages (user_id, original_text_encrypted, encrypted_text, algorithm_used) VALUES (%s, %s, %s, %s)",
                    (session['user_id'], original_encrypted, encrypted_text_db, 'Super Encryption')
                )
                mysql.connection.commit()
                cur.close()
                
                flash('Enkripsi berhasil!', 'success')
                
            except Exception as e:
                flash(f'Error saat enkripsi: {str(e)}', 'danger')
            
        elif action == 'decrypt':
            aes_key_str = request.form.get('aes_key', '')
            if not aes_key_str:
                flash('Masukkan AES key untuk dekripsi!', 'danger')
                return render_template('text_encryption.html')
                
            try:
                aes_key = base64.b64decode(aes_key_str)
                decrypted_text = super_decrypt(text, caesar_shift, vigenere_key, aes_key)
                result = {
                    'type': 'decrypted',
                    'original': text,
                    'result': decrypted_text
                }
                flash('Dekripsi berhasil!', 'success')
            except Exception as e:
                flash('Gagal mendekripsi! Pastikan kunci dan parameter benar.', 'danger')
    
    return render_template('text_encryption.html', result=result)

@app.route('/image-steganography', methods=['GET', 'POST'])
def image_steganography():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'encode':
            if 'image' not in request.files:
                flash('Pilih gambar terlebih dahulu!', 'danger')
                return render_template('image_steganography.html')
            
            image = request.files['image']
            message = request.form.get('message', '')
            
            if image.filename == '':
                flash('Pilih gambar terlebih dahulu!', 'danger')
                return render_template('image_steganography.html')
            
            if not message:
                flash('Masukkan pesan yang ingin disembunyikan!', 'danger')
                return render_template('image_steganography.html')
            
            if image and allowed_file(image.filename, {'png', 'jpg', 'jpeg'}):
                filename = secure_filename(image.filename)
                input_path = os.path.join(app.config['UPLOAD_FOLDER'], 'images', filename)
                output_filename = f'encoded_combined_{filename}'
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'images', output_filename)
                
                image.save(input_path)
                
                try:
                    # Tampilkan pesan processing
                    flash('Memproses gambar...', 'info')
                    
                    advanced_stego.encode_image(input_path, message, output_path, 'combined')
                    result = {
                        'type': 'encoded',
                        'message': message,
                        'output_file': output_filename,
                        'method': 'combined'
                    }
                    flash('Pesan berhasil disembunyikan dengan COMBINED METHOD!', 'success')
                except Exception as e:
                    flash(f'Gagal menyembunyikan pesan: {str(e)}', 'danger')
        
        elif action == 'decode':
            if 'image' not in request.files:
                flash('Pilih gambar terlebih dahulu!', 'danger')
                return render_template('image_steganography.html')
            
            image = request.files['image']
            
            if image.filename == '':
                flash('Pilih gambar terlebih dahulu!', 'danger')
                return render_template('image_steganography.html')
            
            if image and allowed_file(image.filename, {'png', 'jpg', 'jpeg'}):
                filename = secure_filename(image.filename)
                input_path = os.path.join(app.config['UPLOAD_FOLDER'], 'images', filename)
                
                image.save(input_path)
                
                try:
                    # Tampilkan pesan processing
                    flash('Sedang mengekstrak pesan...', 'info')
                    
                    decoded_message = advanced_stego.decode_image(input_path, 'combined')
                    if decoded_message:
                        result = {
                            'type': 'decoded',
                            'message': decoded_message,
                            'method': 'combined'
                        }
                        flash('Pesan berhasil diekstrak!', 'success')
                    else:
                        flash('Tidak ditemukan pesan dalam gambar.', 'warning')
                except Exception as e:
                    flash(f'Gagal mengekstrak pesan: {str(e)}', 'danger')
    
    return render_template('image_steganography.html', result=result)

# File: app.py - Perbaikan bagian file_encryption route
@app.route('/file-encryption', methods=['GET', 'POST'])
def file_encryption():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'encrypt':
            if 'encrypt_file' not in request.files:
                flash('Pilih file terlebih dahulu!', 'danger')
                return render_template('file_encryption.html')
            
            file = request.files['encrypt_file']
            
            if file.filename == '':
                flash('Pilih file terlebih dahulu!', 'danger')
                return render_template('file_encryption.html')
            
            if file and allowed_file(file.filename, {'txt', 'pdf', 'docx', 'doc'}):
                file_data = file.read()
                file.seek(0)
                
                max_rsa_size = 53
                if len(file_data) > max_rsa_size:
                    flash(f'File terlalu besar untuk enkripsi RSA! Maksimal {max_rsa_size} bytes.', 'danger')
                    return render_template('file_encryption.html')
                
                if len(file_data) == 0:
                    flash('File kosong! Pilih file yang berisi data.', 'danger')
                    return render_template('file_encryption.html')
                
                filename = secure_filename(file.filename)
                input_path = os.path.join(app.config['UPLOAD_FOLDER'], 'files', filename)
                output_filename = 'encrypted_' + filename
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'files', output_filename)
                
                file.save(input_path)
                
                try:
                    (pubkey, privkey) = rsa.newkeys(512)
                    encrypted_data = rsa.encrypt(file_data, pubkey)
                    
                    with open(output_path, 'wb') as f:
                        f.write(encrypted_data)
                    
                    privkey_filename = 'private_key_' + filename + '.pem'
                    privkey_path = os.path.join(app.config['UPLOAD_FOLDER'], 'files', privkey_filename)
                    with open(privkey_path, 'wb') as f:
                        f.write(privkey.save_pkcs1())
                    
                    result = {
                        'type': 'encrypted',
                        'input_file': filename,
                        'output_file': output_filename,
                        'private_key_file': privkey_filename
                    }
                    
                    # SIMPAN KE DATABASE DENGAN ENKRIPSI
                    cur = mysql.connection.cursor()
                    
                    # Enkripsi nama file dan path sebelum disimpan
                    filename_encrypted = db_crypto.encrypt(filename)
                    file_path_encrypted = db_crypto.encrypt(output_path)
                    
                    cur.execute(
                        "INSERT INTO encrypted_files (user_id, filename_encrypted, file_path_encrypted, algorithm_used) VALUES (%s, %s, %s, %s)",
                        (session['user_id'], filename_encrypted, file_path_encrypted, 'RSA')
                    )
                    mysql.connection.commit()
                    cur.close()
                    
                    flash('File berhasil dienkripsi!', 'success')
                    
                except Exception as e:
                    flash(f'Gagal mengenkripsi file: {str(e)}', 'danger')
            else:
                flash('Format file tidak didukung!', 'danger')
        elif action == 'decrypt':
            # Hanya proses file dari input decrypt_file dan key_file
            if 'decrypt_file' not in request.files or 'key_file' not in request.files:
                flash('Pilih file terenkripsi dan kunci private terlebih dahulu!', 'danger')
                return render_template('file_encryption.html')
            
            file = request.files['decrypt_file']
            key_file = request.files['key_file']
            
            if file.filename == '' or key_file.filename == '':
                flash('Pilih file terenkripsi dan kunci private terlebih dahulu!', 'danger')
                return render_template('file_encryption.html')
            
            if file and allowed_file(file.filename, {'txt', 'pdf', 'docx', 'doc'}):
                filename = secure_filename(file.filename)
                key_filename = secure_filename(key_file.filename)
                input_path = os.path.join(app.config['UPLOAD_FOLDER'], 'files', filename)
                key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'files', key_filename)
                output_filename = 'decrypted_' + filename
                output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'files', output_filename)
                
                file.save(input_path)
                key_file.save(key_path)
                
                try:
                    # Load private key
                    with open(key_path, 'rb') as f:
                        privkey = rsa.PrivateKey.load_pkcs1(f.read())
                    
                    # Baca file terenkripsi dan dekripsi
                    with open(input_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    decrypted_data = rsa.decrypt(encrypted_data, privkey)
                    
                    # Simpan file terdekripsi
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    
                    result = {
                        'type': 'decrypted',
                        'input_file': filename,
                        'output_file': output_filename
                    }
                    
                    flash('File berhasil didekripsi!', 'success')
                except Exception as e:
                    flash(f'Gagal mendekripsi file: {str(e)}', 'danger')
                    # Clean up files jika ada error
                    if os.path.exists(input_path):
                        os.remove(input_path)
                    if os.path.exists(output_path):
                        os.remove(output_path)
            else:
                flash('Format file tidak didukung! Gunakan TXT, PDF, atau DOCX.', 'danger')
    
    return render_template('file_encryption.html', result=result)

@app.route('/download/<folder>/<filename>')
def download_file(folder, filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, filename)
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        flash('File tidak ditemukan!', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout!', 'info')
    return redirect(url_for('login'))

# File: app.py - Ganti bagian certificate generation
if __name__ == '__main__':
    ssl_context = None
    
    try:
        from OpenSSL import crypto, SSL
        import os
        
        if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
            print("Generating proper self-signed SSL certificate...")
            
            # Buat key pair
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 2048)
            
            # Buat certificate dengan detail yang lebih lengkap
            cert = crypto.X509()
            
            # Set subject details yang lebih proper
            cert.get_subject().C = "ID"
            cert.get_subject().ST = "Yogyakarta"
            cert.get_subject().L = "Yogyakarta"
            cert.get_subject().O = "DFLockApp Dev"
            cert.get_subject().OU = "Development"
            cert.get_subject().CN = "localhost"
            cert.get_subject().emailAddress = "admin@localhost"
            
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365*24*60*60)
            
            # Set issuer (sama dengan subject untuk self-signed)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            
            # PERBAIKAN: Gunakan authorityKeyIdentifier dengan cara yang benar
            extensions = [
                crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
                crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
                crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth, clientAuth"),
                crypto.X509Extension(b"subjectAltName", False, b"DNS:localhost,IP:127.0.0.1")
            ]
            
            # Untuk self-signed, authorityKeyIdentifier bisa menggunakan keyid:always tanpa issuer
            try:
                # Coba buat authorityKeyIdentifier dengan cara sederhana
                auth_key_ext = crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always")
                extensions.insert(2, auth_key_ext)  # Sisipkan di posisi ke-2
            except:
                # Jika gagal, skip authorityKeyIdentifier
                print("ℹ️  Skipping authorityKeyIdentifier extension")
            
            cert.add_extensions(extensions)
            cert.sign(k, 'sha256')
            
            # Save certificate
            with open("cert.pem", "wb") as cert_file:
                cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            with open("key.pem", "wb") as key_file:
                key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
            
            print("✅ SSL certificate generated successfully!")
            print("🔐 Access your app at: https://localhost:5000")
        
        ssl_context = ('cert.pem', 'key.pem')
        
    except ImportError:
        print("⚠️ pyOpenSSL not installed, using adhoc SSL context")
        ssl_context = 'adhoc'
    except Exception as e:
        print(f"❌ Error generating SSL certificate: {e}")
        print("🔄 Falling back to adhoc SSL context")
        ssl_context = 'adhoc'
    
    # Jalankan app
    print("🚀 Starting CryptoApp with HTTPS...")
    app.run(
        debug=True, 
        host='127.0.0.1',
        port=5000,
        ssl_context=ssl_context
    )