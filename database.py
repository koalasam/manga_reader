import os
import logging
import hashlib
import secrets
import threading
import sqlite3
from datetime import datetime, timedelta
from config import *

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global database instance with thread-local connections
_db_instance = None
_db_lock = threading.Lock()

class Database:
    _instance = None
    _local = threading.local()
    
    def __new__(cls, db_file=DATABASE_FILE):
        if cls._instance is None:
            with _db_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.db_file = db_file
                    cls._instance._initialized = False
                    cls._instance.init_db()
        return cls._instance
    
    def get_connection(self):
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            try:
                self._local.conn = sqlite3.connect(
                    self.db_file, 
                    timeout=30.0, 
                    check_same_thread=False,
                    isolation_level=None  # Autocommit mode
                )
                # Enable WAL mode for better concurrency
                self._local.conn.execute('PRAGMA journal_mode=WAL')
                self._local.conn.execute('PRAGMA busy_timeout=30000')
                self._local.conn.execute('PRAGMA synchronous=NORMAL')
            except sqlite3.OperationalError as e:
                logging.error(f"Database connection error: {e}")
                # Return a new connection attempt
                self._local.conn = sqlite3.connect(
                    self.db_file, 
                    timeout=30.0, 
                    check_same_thread=False,
                    isolation_level=None
                )
        return self._local.conn
    
    def init_db(self):
        """Initialize database tables"""
        if self._initialized:
            return
        
        # Ensure database directory exists
        db_dir = os.path.dirname(self.db_file)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, mode=0o777, exist_ok=True)
            except Exception as e:
                logging.error(f"Could not create database directory: {e}")
            
        try:
            conn = sqlite3.connect(self.db_file, timeout=30.0, isolation_level=None)
            cursor = conn.cursor()
            
            # Enable WAL mode
            try:
                cursor.execute('PRAGMA journal_mode=WAL')
                cursor.execute('PRAGMA busy_timeout=30000')
                cursor.execute('PRAGMA synchronous=NORMAL')
            except sqlite3.OperationalError:
                logging.warning("Could not set WAL mode, continuing with default")
            
            # Users table with admin flag and remember_token
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    session_token TEXT,
                    remember_token TEXT,
                    remember_token_expires TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Check if remember_token columns exist, add them if not
            cursor.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'remember_token' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN remember_token TEXT')
                logging.info("Added remember_token column to users table")
            
            if 'remember_token_expires' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN remember_token_expires TIMESTAMP')
                logging.info("Added remember_token_expires column to users table")
            
            # Reading progress table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reading_progress (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    series_name TEXT NOT NULL,
                    chapter_number TEXT NOT NULL,
                    last_page INTEGER DEFAULT 0,
                    completed BOOLEAN DEFAULT FALSE,
                    last_read TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE(user_id, series_name, chapter_number)
                )
            ''')
            
            conn.close()
            self._initialized = True
            
            # Create default admin account
            self.create_default_admin()
        except Exception as e:
            logging.error(f"Error initializing database: {e}")
            raise
    
    def create_default_admin(self):
        """Create default admin account if no users exist"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]
            
            if user_count == 0:
                password_hash = hashlib.sha256('admin'.encode()).hexdigest()
                cursor.execute(
                    'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                    ('admin', password_hash, True)
                )
                logging.info("Default admin account created: username='admin', password='admin'")
        except Exception as e:
            logging.error(f"Error creating default admin: {e}")
    
    def create_user(self, username, password, is_admin=False):
        """Create a new user (admin only)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                (username, password_hash, is_admin)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def change_password(self, user_id, new_password):
        """Change a user's password"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        try:
            cursor.execute(
                'UPDATE users SET password_hash = ?, session_token = NULL, remember_token = NULL, remember_token_expires = NULL WHERE id = ?',
                (password_hash, user_id)
            )
            conn.commit()
            return True
        except:
            return False
    
    def get_all_users(self):
        """Get all users (admin only)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC')
        users = cursor.fetchall()
        
        return [
            {
                'id': user[0],
                'username': user[1],
                'is_admin': bool(user[2]),
                'created_at': user[3]
            }
            for user in users
        ]
    
    def delete_user(self, user_id, current_user_id):
        """Delete a user (admin only, cannot delete self)"""
        if user_id == current_user_id:
            return False
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            cursor.execute('DELETE FROM reading_progress WHERE user_id = ?', (user_id,))
            return True
        except:
            return False
    
    def authenticate_user(self, username, password, remember_me=False):
        """Authenticate a user and return session token"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute(
            'SELECT id, is_admin FROM users WHERE username = ? AND password_hash = ?',
            (username, password_hash)
        )
        
        user = cursor.fetchone()
        
        if user:
            session_token = secrets.token_hex(32)
            
            if remember_me:
                # Create a remember token that expires in 30 days
                remember_token = secrets.token_hex(32)
                expires = datetime.now() + timedelta(days=30)
                
                cursor.execute(
                    'UPDATE users SET session_token = ?, remember_token = ?, remember_token_expires = ? WHERE id = ?',
                    (session_token, remember_token, expires, user[0])
                )
                
                return {
                    'token': session_token,
                    'is_admin': bool(user[1]),
                    'remember_token': remember_token,
                    'remember_expires': expires
                }
            else:
                cursor.execute(
                    'UPDATE users SET session_token = ? WHERE id = ?',
                    (session_token, user[0])
                )
                
                return {
                    'token': session_token,
                    'is_admin': bool(user[1])
                }
        else:
            return None
    
    def get_user_by_token(self, session_token):
        """Get user by session token"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, username, is_admin FROM users WHERE session_token = ?',
            (session_token,)
        )
        
        user = cursor.fetchone()
        
        if user:
            return {'id': user[0], 'username': user[1], 'is_admin': bool(user[2])}
        return None
    
    def get_user_by_remember_token(self, remember_token):
        """Get user by remember token and create new session if valid"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, username, is_admin, remember_token_expires FROM users WHERE remember_token = ?',
            (remember_token,)
        )
        
        user = cursor.fetchone()
        
        if user:
            # Check if token is still valid
            expires = datetime.fromisoformat(user[3]) if user[3] else None
            
            if expires and expires > datetime.now():
                # Token is valid, create new session
                session_token = secrets.token_hex(32)
                cursor.execute(
                    'UPDATE users SET session_token = ? WHERE id = ?',
                    (session_token, user[0])
                )
                
                return {
                    'id': user[0],
                    'username': user[1],
                    'is_admin': bool(user[2]),
                    'session_token': session_token
                }
            else:
                # Token expired, clear it
                cursor.execute(
                    'UPDATE users SET remember_token = NULL, remember_token_expires = NULL WHERE id = ?',
                    (user[0],)
                )
        
        return None
    
    def clear_remember_token(self, user_id):
        """Clear remember token for a user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE users SET remember_token = NULL, remember_token_expires = NULL WHERE id = ?',
            (user_id,)
        )
    
    def update_reading_progress(self, user_id, series_name, chapter_number, last_page, completed=False):
        """Update reading progress for a user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO reading_progress 
            (user_id, series_name, chapter_number, last_page, completed, last_read)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, series_name, chapter_number, last_page, completed))
    
    def get_reading_progress(self, user_id, series_name=None):
        """Get reading progress for a user"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if series_name:
            cursor.execute('''
                SELECT series_name, chapter_number, last_page, completed, last_read
                FROM reading_progress 
                WHERE user_id = ? AND series_name = ?
                ORDER BY last_read DESC
            ''', (user_id, series_name))
        else:
            cursor.execute('''
                SELECT series_name, chapter_number, last_page, completed, last_read
                FROM reading_progress 
                WHERE user_id = ? 
                ORDER BY last_read DESC
            ''', (user_id,))
        
        progress = cursor.fetchall()
        
        result = {}
        for row in progress:
            series, chapter, last_page, completed, last_read = row
            if series not in result:
                result[series] = {}
            result[series][chapter] = {
                'last_page': last_page,
                'completed': bool(completed),
                'last_read': last_read
            }
        
        return result
    
    def get_series_progress(self, user_id, series_name):
        """Get progress for a specific series"""
        progress = self.get_reading_progress(user_id, series_name)
        return progress.get(series_name, {})
    
    def get_continue_reading(self, user_id, limit=5):
        """Get recently read series for continue reading"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT series_name, MAX(last_read) as latest_read
            FROM reading_progress 
            WHERE user_id = ? 
            GROUP BY series_name
            ORDER BY latest_read DESC
            LIMIT ?
        ''', (user_id, limit))
        
        series_list = cursor.fetchall()
        
        return [series[0] for series in series_list]