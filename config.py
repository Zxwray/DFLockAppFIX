import os

class Config:
    SECRET_KEY = 'your-secret-key-here'
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