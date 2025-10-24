#!/usr/bin/env python3
"""
Manga Web Server with Accounts and Reading Progress
Serves manga from a directory structure with a clean web interface.
"""

import os
import sys
import json
import glob
import logging
import re
import hashlib
import secrets
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import sqlite3
from datetime import datetime

# Configuration - use environment variables with your specific paths
MANGA_DIR = '/mnt/nas_share/Media/Manga'
PORT = 9008
HOST = '0.0.0.0'
DATABASE_FILE = os.getenv('DATABASE_FILE', '/data/manga.db')
ACCENT_COLOR = "#8b5cf6"  # Purple accent

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
            except sqlite3.OperationalError:
                logging.warning("Could not set WAL mode, continuing with default")
            
            # Users table with admin flag
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    session_token TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
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
                'UPDATE users SET password_hash = ?, session_token = NULL WHERE id = ?',
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
    
    def authenticate_user(self, username, password):
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
            cursor.execute(
                'UPDATE users SET session_token = ? WHERE id = ?',
                (session_token, user[0])
            )
            return {'token': session_token, 'is_admin': bool(user[1])}
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

class MangaRequestHandler(SimpleHTTPRequestHandler):
    # Class-level database instance shared across all requests
    db = None
    
    def __init__(self, *args, **kwargs):
        # Initialize class-level database if not already done
        if MangaRequestHandler.db is None:
            MangaRequestHandler.db = Database()
        super().__init__(*args, **kwargs)
    
    def get_current_user(self):
        """Get current user from session cookie"""
        cookie_header = self.headers.get('Cookie', '')
        cookies = parse_qs(cookie_header.replace('; ', '&'))
        
        session_token = cookies.get('session_token', [None])[0]
        if session_token:
            return self.db.get_user_by_token(session_token)
        return None
    
    def require_auth(self):
        """Redirect to login if not authenticated"""
        user = self.get_current_user()
        if not user:
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return None
        return user
    
    def require_admin(self):
        """Redirect to home if not admin"""
        user = self.require_auth()
        if not user or not user.get('is_admin'):
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return None
        return user
    
    def set_session_cookie(self, session_token):
        """Set session cookie"""
        self.send_header('Set-Cookie', f'session_token={session_token}; Path=/; HttpOnly')
    
    def clear_session_cookie(self):
        """Clear session cookie"""
        self.send_header('Set-Cookie', 'session_token=; Path=/; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
    
    def do_GET(self):
        # Parse the URL path
        parsed_path = urlparse(self.path)
        path = unquote(parsed_path.path)
        
        # Route handling - require auth for all pages except login
        if path == '/login':
            self.serve_login_page()
        elif path == '/logout':
            self.do_logout()
        else:
            # Require authentication for all other pages
            user = self.require_auth()
            if not user:
                return
            
            if path == '/':
                self.serve_homepage()
            elif path == '/admin':
                self.serve_admin_page()
            elif path == '/my-progress':
                self.serve_progress_page()
            elif path.startswith('/series/'):
                series_name = path.split('/')[2]
                self.serve_series_page(series_name)
            elif path.startswith('/chapter/'):
                parts = path.split('/')
                series_name = parts[2]
                chapter_number = parts[3]
                self.serve_chapter_page(series_name, chapter_number)
            elif path.startswith('/image/'):
                parts = path.split('/')
                series_name = parts[2]
                chapter_number = parts[3]
                image_name = parts[4]
                self.serve_image(series_name, chapter_number, image_name)
            else:
                # Serve static files if they exist
                if os.path.exists('.' + path):
                    super().do_GET()
                else:
                    self.send_error(404, "File not found")
    
    def do_POST(self):
        """Handle POST requests for login/admin actions"""
        parsed_path = urlparse(self.path)
        path = unquote(parsed_path.path)
        
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        form_data = parse_qs(post_data)
        
        if path == '/login':
            self.do_login(form_data)
        elif path == '/admin/create_user':
            self.do_create_user(form_data)
        elif path == '/admin/delete_user':
            self.do_delete_user(form_data)
        elif path == '/admin/change_password':
            self.do_change_password(form_data)
        elif path.startswith('/api/progress/'):
            self.update_reading_progress_api(path, form_data)
        else:
            self.send_error(404, "Not found")
    
    def do_login(self, form_data):
        """Handle login form submission"""
        username = form_data.get('username', [''])[0]
        password = form_data.get('password', [''])[0]
        
        auth_result = self.db.authenticate_user(username, password)
        
        if auth_result:
            self.send_response(302)
            self.set_session_cookie(auth_result['token'])
            self.send_header('Location', '/')
            self.end_headers()
        else:
            self.serve_login_page(error="Invalid username or password")
    
    def do_create_user(self, form_data):
        """Handle user creation (admin only)"""
        admin_user = self.require_admin()
        if not admin_user:
            return
        
        username = form_data.get('username', [''])[0]
        password = form_data.get('password', [''])[0]
        is_admin = form_data.get('is_admin', [''])[0] == 'on'
        
        if len(username) < 3:
            self.serve_admin_page(error="Username must be at least 3 characters")
            return
        
        if len(password) < 6:
            self.serve_admin_page(error="Password must be at least 6 characters")
            return
        
        if self.db.create_user(username, password, is_admin):
            self.serve_admin_page(message=f"User '{username}' created successfully")
        else:
            self.serve_admin_page(error="Username already exists")
    
    def do_delete_user(self, form_data):
        """Handle user deletion (admin only)"""
        admin_user = self.require_admin()
        if not admin_user:
            return
        
        user_id = int(form_data.get('user_id', [0])[0])
        
        if self.db.delete_user(user_id, admin_user['id']):
            self.serve_admin_page(message="User deleted successfully")
        else:
            self.serve_admin_page(error="Cannot delete user")
    
    def do_change_password(self, form_data):
        """Handle password change (admin only)"""
        admin_user = self.require_admin()
        if not admin_user:
            return
        
        user_id = int(form_data.get('user_id', [0])[0])
        new_password = form_data.get('new_password', [''])[0]
        
        if len(new_password) < 6:
            self.serve_admin_page(error="Password must be at least 6 characters")
            return
        
        if self.db.change_password(user_id, new_password):
            self.serve_admin_page(message="Password changed successfully")
        else:
            self.serve_admin_page(error="Failed to change password")
    
    def do_logout(self):
        """Handle logout"""
        user = self.get_current_user()
        if user:
            # In a real implementation, you'd invalidate the session token in the database
            pass
        
        self.send_response(302)
        self.clear_session_cookie()
        self.send_header('Location', '/login')
        self.end_headers()
    
    def update_reading_progress_api(self, path, form_data):
        """Update reading progress via API"""
        user = self.require_auth()
        if not user:
            return
        
        # Extract series and chapter from path: /api/progress/series/chapter
        parts = path.split('/')
        if len(parts) < 5:
            self.send_error(400, "Invalid path")
            return
        
        series_name = parts[3]
        chapter_number = parts[4]
        last_page = int(form_data.get('last_page', [0])[0])
        completed = bool(form_data.get('completed', [False])[0])
        
        self.db.update_reading_progress(
            user['id'], series_name, chapter_number, last_page, completed
        )
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'status': 'success'}).encode())
    
    def serve_homepage(self):
        """Serve the homepage with all series"""
        try:
            user = self.get_current_user()
            series_list = []
            
            for series in sorted(os.listdir(MANGA_DIR)):
                series_path = os.path.join(MANGA_DIR, series)
                if os.path.isdir(series_path):
                    # Find the first chapter using natural sorting
                    chapters = self.get_chapters_sorted(series_path)
                    if chapters:
                        first_chapter = chapters[0]
                        # Find the first image in the first chapter
                        images = sorted(glob.glob(os.path.join(series_path, first_chapter, "*.jpg")))
                        if not images:
                            images = sorted(glob.glob(os.path.join(series_path, first_chapter, "*.jpeg")))
                        if not images:
                            images = sorted(glob.glob(os.path.join(series_path, first_chapter, "*.png")))
                        
                        if images:
                            preview_url = f"/image/{series}/{first_chapter}/{os.path.basename(images[0])}"
                            # Clean up series name for display
                            display_name = series.replace("-", " ").replace("_", " ").title()
                            
                            # Get reading progress for this series
                            progress = None
                            if user:
                                series_progress = self.db.get_series_progress(user['id'], series)
                                progress = self.calculate_series_progress(series_progress, chapters)
                            
                            series_list.append({
                                'name': series,
                                'display_name': display_name,
                                'preview_url': preview_url,
                                'chapter_count': len(chapters),
                                'progress': progress
                            })
            
            html = self.generate_homepage(series_list, user)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            logging.error(f"Error serving homepage: {e}")
            self.send_error(500, f"Server error: {e}")
    
    def serve_login_page(self, error=None):
        """Serve the login page"""
        html = self.generate_login_page(error)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def serve_admin_page(self, error=None, message=None):
        """Serve the admin page"""
        admin_user = self.require_admin()
        if not admin_user:
            return
        
        try:
            users = self.db.get_all_users()
            html = self.generate_admin_page(users, error, message)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            logging.error(f"Error serving admin page: {e}")
            self.send_error(500, f"Server error: {e}")
    
    def serve_progress_page(self):
        """Serve the reading progress page"""
        user = self.require_auth()
        if not user:
            return
        
        try:
            progress = self.db.get_reading_progress(user['id'])
            continue_reading = self.db.get_continue_reading(user['id'])
            
            html = self.generate_progress_page(user, progress, continue_reading)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            logging.error(f"Error serving progress page: {e}")
            self.send_error(500, f"Server error: {e}")
    
    def serve_series_page(self, series_name):
        """Serve a page for a specific series showing all chapters"""
        try:
            user = self.require_auth()
            if not user:
                return
                
            series_path = os.path.join(MANGA_DIR, series_name)
            if not os.path.exists(series_path):
                self.send_error(404, f"Series '{series_name}' not found")
                return
            
            # Clean up series name for display
            display_name = series_name.replace("-", " ").replace("_", " ").title()
            
            # Get chapters sorted numerically
            chapters_sorted = self.get_chapters_sorted(series_path)
            
            # Get reading progress for this series
            series_progress = {}
            if user:
                series_progress = self.db.get_series_progress(user['id'], series_name)
            
            chapters = []
            for chapter in chapters_sorted:
                chapter_path = os.path.join(series_path, chapter)
                if os.path.isdir(chapter_path):
                    # Find the first image in the chapter
                    images = sorted(glob.glob(os.path.join(chapter_path, "*.jpg")))
                    if not images:
                        images = sorted(glob.glob(os.path.join(chapter_path, "*.jpeg")))
                    if not images:
                        images = sorted(glob.glob(os.path.join(chapter_path, "*.png")))
                    
                    if images:
                        preview_url = f"/image/{series_name}/{chapter}/{os.path.basename(images[0])}"
                        # Clean up chapter number for display
                        chapter_num = self.clean_chapter_number(chapter)
                        
                        # Get progress for this chapter
                        chapter_progress = series_progress.get(chapter, {})
                        
                        chapters.append({
                            'number': chapter,
                            'display_number': chapter_num,
                            'preview_url': preview_url,
                            'page_count': len(images),
                            'progress': chapter_progress
                        })
            
            html = self.generate_series_page(series_name, display_name, chapters, user)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            logging.error(f"Error serving series page: {e}")
            self.send_error(500, f"Server error: {e}")
    
    def serve_chapter_page(self, series_name, chapter_number):
        """Serve a page for reading a specific chapter"""
        try:
            user = self.require_auth()
            if not user:
                return
                
            chapter_path = os.path.join(MANGA_DIR, series_name, chapter_number)
            if not os.path.exists(chapter_path):
                self.send_error(404, f"Chapter '{chapter_number}' not found in series '{series_name}'")
                return
            
            # Clean up series name for display
            display_name = series_name.replace("-", " ").replace("_", " ").title()
            # Clean up chapter number for display
            display_chapter = self.clean_chapter_number(chapter_number)
            
            # Get all chapters for navigation (sorted numerically)
            series_path = os.path.join(MANGA_DIR, series_name)
            all_chapters = self.get_chapters_sorted(series_path)
            
            # Find current chapter index
            current_index = all_chapters.index(chapter_number)
            prev_chapter = all_chapters[current_index - 1] if current_index > 0 else None
            next_chapter = all_chapters[current_index + 1] if current_index < len(all_chapters) - 1 else None
            
            # Find all images in the chapter
            images = sorted(glob.glob(os.path.join(chapter_path, "*.jpg")))
            if not images:
                images = sorted(glob.glob(os.path.join(chapter_path, "*.jpeg")))
            if not images:
                images = sorted(glob.glob(os.path.join(chapter_path, "*.png")))
            
            if not images:
                self.send_error(404, f"No images found in chapter '{chapter_number}'")
                return
            
            image_urls = [f"/image/{series_name}/{chapter_number}/{os.path.basename(img)}" for img in images]
            
            # Get reading progress for this chapter
            current_progress = None
            if user:
                series_progress = self.db.get_series_progress(user['id'], series_name)
                current_progress = series_progress.get(chapter_number, {})
            
            html = self.generate_chapter_page(
                series_name, display_name, chapter_number, display_chapter, 
                image_urls, prev_chapter, next_chapter, user, current_progress
            )
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            logging.error(f"Error serving chapter page: {e}")
            self.send_error(500, f"Server error: {e}")
    
    def serve_image(self, series_name, chapter_number, image_name):
        """Serve an image file"""
        try:
            user = self.require_auth()
            if not user:
                return
                
            image_path = os.path.join(MANGA_DIR, series_name, chapter_number, image_name)
            if not os.path.exists(image_path):
                self.send_error(404, f"Image '{image_name}' not found")
                return
            
            # Determine content type based on file extension
            ext = os.path.splitext(image_name)[1].lower()
            if ext in ['.jpg', '.jpeg']:
                content_type = 'image/jpeg'
            elif ext == '.png':
                content_type = 'image/png'
            else:
                self.send_error(415, f"Unsupported image format: {ext}")
                return
            
            with open(image_path, 'rb') as f:
                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.end_headers()
                self.wfile.write(f.read())
        except Exception as e:
            logging.error(f"Error serving image: {e}")
            self.send_error(500, f"Server error: {e}")
    
    def get_chapters_sorted(self, series_path):
        """Get chapters sorted numerically rather than lexicographically"""
        if not os.path.exists(series_path):
            return []
        
        # Get all directories (chapters)
        chapters = [d for d in os.listdir(series_path) if os.path.isdir(os.path.join(series_path, d))]
        
        # Sort numerically by extracting numbers from chapter names
        def extract_number(chapter_name):
            # Try to find numbers in the chapter name
            numbers = re.findall(r'\d+', chapter_name)
            if numbers:
                # Use the first number found
                return int(numbers[0])
            # If no numbers found, use a high value to push to end
            return 999999
        
        # Sort by extracted number, then by original name for consistency
        return sorted(chapters, key=lambda x: (extract_number(x), x))

    def clean_chapter_number(self, chapter_str):
        """Clean up chapter number for display"""
        # Remove leading zeros and any non-numeric prefixes
        match = re.search(r'(\d+\.?\d*)', chapter_str)
        if match:
            # Convert to float and back to string to remove trailing .0 if needed
            num = float(match.group(1))
            if num.is_integer():
                return f"Chapter {int(num)}"
            else:
                return f"Chapter {num}"
        
        # If no numbers found, just return the original string with formatting
        return chapter_str.replace("-", " ").replace("_", " ").title()
    
    def calculate_series_progress(self, series_progress, all_chapters):
        """Calculate overall progress for a series"""
        if not series_progress:
            return 0
        
        completed_chapters = sum(1 for chapter_progress in series_progress.values() 
                               if chapter_progress.get('completed', False))
        
        return int((completed_chapters / len(all_chapters)) * 100) if all_chapters else 0

    def generate_homepage(self, series_list, user):
        """Generate HTML for the homepage"""
        admin_button = ""
        if user.get('is_admin'):
            admin_button = '<a href="/admin" class="button admin-button">Admin Panel</a>'
        
        auth_section = f"""
        <div class="user-info">
            <span>Welcome, {user['username']}</span>
            <div class="user-actions">
                <a href="/my-progress" class="button">My Progress</a>
                {admin_button}
                <a href="/logout" class="button logout">Logout</a>
            </div>
        </div>
        """
        
        # Continue reading section
        continue_reading = ""
        continue_series = self.db.get_continue_reading(user['id'])
        if continue_series:
            continue_cards = ""
            for series_name in continue_series[:4]:  # Show max 4 series
                series_path = os.path.join(MANGA_DIR, series_name)
                if os.path.exists(series_path):
                    chapters = self.get_chapters_sorted(series_path)
                    if chapters:
                        first_chapter = chapters[0]
                        images = sorted(glob.glob(os.path.join(series_path, first_chapter, "*.jpg")))
                        if not images:
                            images = sorted(glob.glob(os.path.join(series_path, first_chapter, "*.png")))
                        
                        if images:
                            preview_url = f"/image/{series_name}/{first_chapter}/{os.path.basename(images[0])}"
                            display_name = series_name.replace("-", " ").replace("_", " ").title()
                            series_progress = self.db.get_series_progress(user['id'], series_name)
                            progress = self.calculate_series_progress(series_progress, chapters)
                            
                            progress_bar = f"""
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: {progress}%"></div>
                            </div>
                            <div class="progress-text">{progress}% complete</div>
                            """ if progress > 0 else ""
                            
                            continue_cards += f"""
                            <a href="/series/{series_name}" class="series-card">
                                <div class="card">
                                    <img src="{preview_url}" alt="{display_name}">
                                    <div class="card-content">
                                        <h3>{display_name}</h3>
                                        {progress_bar}
                                    </div>
                                </div>
                            </a>
                            """
            
            if continue_cards:
                continue_reading = f"""
                <section class="continue-reading">
                    <h2>Continue Reading</h2>
                    <div class="series-grid">
                        {continue_cards}
                    </div>
                </section>
                """
        
        series_cards = ""
        for series in series_list:
            progress_indicator = ""
            if series['progress'] is not None and series['progress'] > 0:
                progress_indicator = f"""
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {series['progress']}%"></div>
                </div>
                <div class="progress-text">{series['progress']}% complete</div>
                """
            
            series_cards += f"""
            <a href="/series/{series['name']}" class="series-card">
                <div class="card">
                    <img src="{series['preview_url']}" alt="{series['display_name']}">
                    <div class="card-content">
                        <h3>{series['display_name']}</h3>
                        <p>{series['chapter_count']} chapters</p>
                        {progress_indicator}
                    </div>
                </div>
            </a>
            """
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Manga Library</title>
            <style>
                {self.get_css()}
            </style>
        </head>
        <body>
            <header>
                <h1>Manga Library</h1>
                <div class="header-actions">
                    {auth_section}
                    <button id="theme-toggle">Toggle Theme</button>
                </div>
            </header>
            <main>
                {continue_reading}
                <section class="all-series">
                    <h2>All Series</h2>
                    <div class="series-grid">
                        {series_cards}
                    </div>
                </section>
            </main>
            <script>
                {self.get_js()}
            </script>
        </body>
        </html>
        """
    
    def generate_login_page(self, error=None):
        """Generate HTML for login page"""
        error_msg = f'<div class="error-message">{error}</div>' if error else ''
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - Manga Library</title>
            <style>
                {self.get_css()}
            </style>
        </head>
        <body>
            <header>
                <h1><a href="/" style="color: inherit; text-decoration: none;">Manga Library</a></h1>
            </header>
            <main class="auth-page">
                <div class="auth-container">
                    <h2>Login</h2>
                    {error_msg}
                    <form method="POST" action="/login" class="auth-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <button type="submit" class="button">Login</button>
                    </form>
                    <div class="login-info">
                        <p><strong>Default Admin Account:</strong></p>
                        <p>Username: <code>admin</code></p>
                        <p>Password: <code>admin</code></p>
                        <p><em>Please change the default password after first login!</em></p>
                    </div>
                </div>
            </main>
            <script>
                {self.get_js()}
            </script>
        </body>
        </html>
        """
    
    def generate_admin_page(self, users, error=None, message=None):
        """Generate HTML for admin page"""
        error_msg = f'<div class="error-message">{error}</div>' if error else ''
        success_msg = f'<div class="success-message">{message}</div>' if message else ''
        
        users_list = ""
        for user in users:
            admin_badge = " <span class='admin-badge'>Admin</span>" if user['is_admin'] else ""
            delete_button = ""
            change_password_form = f"""
            <form method="POST" action="/admin/change_password" class="password-form">
                <input type="hidden" name="user_id" value="{user['id']}">
                <input type="password" name="new_password" placeholder="New password" required minlength="6">
                <button type="submit" class="button password-button">Change Password</button>
            </form>
            """
            
            if not user['is_admin'] or len([u for u in users if u['is_admin']]) > 1:
                delete_button = f"""
                <form method="POST" action="/admin/delete_user" style="display: inline;">
                    <input type="hidden" name="user_id" value="{user['id']}">
                    <button type="submit" class="button danger" onclick="return confirm('Are you sure you want to delete user {user['username']}?')">Delete</button>
                </form>
                """
            
            users_list += f"""
            <tr>
                <td>{user['username']}{admin_badge}</td>
                <td>{'Yes' if user['is_admin'] else 'No'}</td>
                <td>{user['created_at']}</td>
                <td class="actions-cell">
                    {change_password_form}
                    {delete_button}
                </td>
            </tr>
            """
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Admin Panel - Manga Library</title>
            <style>
                {self.get_css()}
            </style>
        </head>
        <body>
            <header>
                <a href="/" class="back-button">← Back to Library</a>
                <h1>Admin Panel</h1>
                <div class="header-actions">
                    <div class="user-info">
                        <span>Welcome, Admin</span>
                    </div>
                    <button id="theme-toggle">Toggle Theme</button>
                </div>
            </header>
            <main>
                <div class="admin-container">
                    {error_msg}
                    {success_msg}
                    
                    <section class="create-user-section">
                        <h2>Create New User</h2>
                        <form method="POST" action="/admin/create_user" class="auth-form">
                            <div class="form-group">
                                <label for="username">Username:</label>
                                <input type="text" id="username" name="username" required minlength="3">
                            </div>
                            <div class="form-group">
                                <label for="password">Password:</label>
                                <input type="password" id="password" name="password" required minlength="6">
                            </div>
                            <div class="form-group checkbox-group">
                                <label>
                                    <input type="checkbox" id="is_admin" name="is_admin">
                                    Admin User
                                </label>
                            </div>
                            <button type="submit" class="button">Create User</button>
                        </form>
                    </section>
                    
                    <section class="users-section">
                        <h2>User Management</h2>
                        <div class="table-container">
                            <table class="users-table">
                                <thead>
                                    <tr>
                                        <th>Username</th>
                                        <th>Admin</th>
                                        <th>Created</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {users_list}
                                </tbody>
                            </table>
                        </div>
                    </section>
                </div>
            </main>
            <script>
                {self.get_js()}
            </script>
        </body>
        </html>
        """
    
    def generate_progress_page(self, user, progress, continue_reading):
        """Generate HTML for reading progress page"""
        progress_items = ""
        
        if progress:
            for series_name, chapters in progress.items():
                series_path = os.path.join(MANGA_DIR, series_name)
                if os.path.exists(series_path):
                    all_chapters = self.get_chapters_sorted(series_path)
                    series_progress = self.calculate_series_progress(chapters, all_chapters)
                    display_name = series_name.replace("-", " ").replace("_", " ").title()
                    
                    # Find the first chapter for preview
                    first_chapter = all_chapters[0] if all_chapters else ""
                    images = sorted(glob.glob(os.path.join(series_path, first_chapter, "*.jpg"))) if first_chapter else []
                    if not images and first_chapter:
                        images = sorted(glob.glob(os.path.join(series_path, first_chapter, "*.png")))
                    
                    preview_url = f"/image/{series_name}/{first_chapter}/{os.path.basename(images[0])}" if images else ""
                    
                    progress_items += f"""
                    <div class="progress-item">
                        <a href="/series/{series_name}" class="progress-card">
                            <div class="card">
                                <img src="{preview_url}" alt="{display_name}">
                                <div class="card-content">
                                    <h3>{display_name}</h3>
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: {series_progress}%"></div>
                                    </div>
                                    <div class="progress-text">{series_progress}% complete</div>
                                    <div class="chapter-progress">
                                        {len(chapters)}/{len(all_chapters)} chapters read
                                    </div>
                                </div>
                            </div>
                        </a>
                    </div>
                    """
        else:
            progress_items = '<p class="no-progress">No reading progress yet. Start reading some manga!</p>'
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>My Progress - Manga Library</title>
            <style>
                {self.get_css()}
            </style>
        </head>
        <body>
            <header>
                <a href="/" class="back-button">← Back to Library</a>
                <h1>My Reading Progress</h1>
                <div class="header-actions">
                    <div class="user-info">
                        <span>Welcome, {user['username']}</span>
                    </div>
                    <button id="theme-toggle">Toggle Theme</button>
                </div>
            </header>
            <main>
                <div class="progress-grid">
                    {progress_items}
                </div>
            </main>
            <script>
                {self.get_js()}
            </script>
        </body>
        </html>
        """
    
    def generate_series_page(self, series_name, display_name, chapters, user):
        """Generate HTML for a series page showing all chapters"""
        chapter_cards = ""
        for chapter in chapters:
            progress_indicator = ""
            if chapter['progress']:
                if chapter['progress'].get('completed', False):
                    progress_indicator = '<div class="chapter-status completed">✓ Completed</div>'
                elif chapter['progress'].get('last_page', 0) > 0:
                    progress_percent = int((chapter['progress']['last_page'] / chapter['page_count']) * 100)
                    progress_indicator = f"""
                    <div class="progress-bar small">
                        <div class="progress-fill" style="width: {progress_percent}%"></div>
                    </div>
                    <div class="progress-text">{progress_percent}% read</div>
                    """
            
            chapter_cards += f"""
            <a href="/chapter/{series_name}/{chapter['number']}" class="chapter-card">
                <div class="card">
                    <img src="{chapter['preview_url']}" alt="{chapter['display_number']}">
                    <div class="card-content">
                        <h3>{chapter['display_number']}</h3>
                        <p>{chapter['page_count']} pages</p>
                        {progress_indicator}
                    </div>
                </div>
            </a>
            """
        
        admin_button = ""
        if user.get('is_admin'):
            admin_button = '<a href="/admin" class="button admin-button">Admin Panel</a>'
        
        auth_section = f"""
        <div class="user-info">
            <span>{user['username']}</span>
            <div class="user-actions">
                <a href="/my-progress" class="button">My Progress</a>
                {admin_button}
                <a href="/logout" class="button logout">Logout</a>
            </div>
        </div>
        """
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{display_name} - Manga Library</title>
            <style>
                {self.get_css()}
            </style>
        </head>
        <body>
            <header>
                <a href="/" class="back-button">← Back to Library</a>
                <h1>{display_name}</h1>
                <div class="header-actions">
                    {auth_section}
                    <button id="theme-toggle">Toggle Theme</button>
                </div>
            </header>
            <main>
                <div class="chapters-grid">
                    {chapter_cards}
                </div>
            </main>
            <script>
                {self.get_js()}
            </script>
        </body>
        </html>
        """
    
    def generate_chapter_page(self, series_name, display_name, chapter_number, display_chapter, 
                            image_urls, prev_chapter, next_chapter, user, current_progress):
        """Generate HTML for a chapter reading page"""
        images_html = ""
        for i, img_url in enumerate(image_urls):
            page_num = i + 1
            is_current = current_progress and current_progress.get('last_page', 0) >= page_num
            current_class = "current-page" if is_current else ""
            images_html += f'<img src="{img_url}" class="manga-page {current_class}" alt="Page {page_num}" data-page="{page_num}">'
        
        # Navigation buttons
        nav_buttons = ""
        if prev_chapter:
            prev_display = self.clean_chapter_number(prev_chapter)
            nav_buttons += f'<a href="/chapter/{series_name}/{prev_chapter}" class="nav-button prev-button">← {prev_display}</a>'
        else:
            nav_buttons += '<div class="nav-button disabled">← Previous</div>'
            
        nav_buttons += f'<a href="/series/{series_name}" class="nav-button series-button">Back to {display_name}</a>'
        
        if next_chapter:
            next_display = self.clean_chapter_number(next_chapter)
            nav_buttons += f'<a href="/chapter/{series_name}/{next_chapter}" class="nav-button next-button">{next_display} →</a>'
        else:
            nav_buttons += '<div class="nav-button disabled">Next →</div>'
        
        # Progress tracking
        progress_tracker = """
        <div class="progress-tracker">
            <label>
                <input type="checkbox" id="mark-completed">
                Mark as completed
            </label>
        </div>
        """
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{display_name} - {display_chapter}</title>
            <style>
                {self.get_css()}
            </style>
        </head>
        <body>
            <header>
                <a href="/series/{series_name}" class="back-button">← Back to {display_name}</a>
                <h1>{display_name} - {display_chapter}</h1>
                <button id="theme-toggle">Toggle Theme</button>
            </header>
            
            <div class="chapter-nav top-nav">
                {nav_buttons}
                {progress_tracker}
            </div>
            
            <main class="reader">
                {images_html}
            </main>
            
            <div class="chapter-nav bottom-nav">
                {nav_buttons}
            </div>
            
            <script>
                {self.get_js_with_progress(series_name, chapter_number, len(image_urls))}
            </script>
        </body>
        </html>
        """
    
    def get_js_with_progress(self, series_name, chapter_number, total_pages):
        """Return JavaScript with progress tracking"""
        base_js = self.get_js()
        
        progress_js = f"""
        // Progress tracking
        document.addEventListener('DOMContentLoaded', function() {{
            const totalPages = {total_pages};
            const seriesName = '{series_name}';
            const chapterNumber = '{chapter_number}';
            let currentPage = 0;
            
            // Track page visibility
            const observer = new IntersectionObserver((entries) => {{
                entries.forEach(entry => {{
                    if (entry.isIntersecting) {{
                        const pageNum = parseInt(entry.target.dataset.page);
                        if (pageNum > currentPage) {{
                            currentPage = pageNum;
                            updateProgress(currentPage, false);
                        }}
                    }}
                }});
            }}, {{ threshold: 0.5 }});
            
            // Observe all pages
            document.querySelectorAll('.manga-page').forEach(page => {{
                observer.observe(page);
            }});
            
            // Mark as completed checkbox
            const markCompleted = document.getElementById('mark-completed');
            if (markCompleted) {{
                markCompleted.addEventListener('change', function() {{
                    if (this.checked) {{
                        currentPage = totalPages;
                        updateProgress(currentPage, true);
                    }}
                }});
            }}
            
            // Update progress on server
            function updateProgress(lastPage, completed) {{
                const formData = new FormData();
                formData.append('last_page', lastPage);
                formData.append('completed', completed);
                
                fetch(`/api/progress/${{seriesName}}/${{chapterNumber}}`, {{
                    method: 'POST',
                    body: formData
                }}).then(response => {{
                    if (response.ok) {{
                        console.log('Progress updated');
                    }}
                }});
            }}
            
            // Update page when reaching the end
            window.addEventListener('scroll', function() {{
                if ((window.innerHeight + window.scrollY) >= document.body.offsetHeight - 100) {{
                    if (currentPage === totalPages - 1) {{
                        currentPage = totalPages;
                        updateProgress(currentPage, true);
                        if (markCompleted) {{
                            markCompleted.checked = true;
                        }}
                    }}
                }}
            }});
        }});
        """
        
        return base_js + progress_js

    def get_css(self):
        """Return the CSS for the site"""
        base_css = f"""
        :root {{
            --accent-color: {ACCENT_COLOR};
            --bg-color: #f5f5f5;
            --text-color: #333;
            --card-bg: #fff;
            --border-color: #e0e0e0;
        }}

        [data-theme="dark"] {{
            --bg-color: #1a1a1a;
            --text-color: #f5f5f5;
            --card-bg: #2d2d2d;
            --border-color: #404040;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding-bottom: 2rem;
        }}

        header {{
            background-color: var(--card-bg);
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 1rem;
        }}

        .back-button {{
            color: var(--accent-color);
            text-decoration: none;
            font-weight: 500;
        }}

        h1 {{
            font-size: 1.5rem;
            margin: 0;
        }}

        .header-actions {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .user-info {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .user-actions {{
            display: flex;
            gap: 0.5rem;
        }}

        .button {{
            background-color: var(--accent-color);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            text-decoration: none;
            font-weight: 500;
            border: none;
            cursor: pointer;
            display: inline-block;
            font-size: 0.9rem;
        }}

        .button.admin-button {{
            background-color: #059669;
        }}

        .button.logout {{
            background-color: #dc2626;
        }}

        .button.danger {{
            background-color: #dc2626;
            font-size: 0.8rem;
            padding: 0.25rem 0.5rem;
        }}

        .button.password-button {{
            background-color: #d97706;
            font-size: 0.8rem;
            padding: 0.25rem 0.5rem;
        }}

        .button:hover {{
            opacity: 0.9;
        }}

        #theme-toggle {{
            background-color: var(--accent-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
        }}

        main {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }}

        .auth-page {{
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 80vh;
        }}

        .auth-container {{
            background-color: var(--card-bg);
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }}

        .admin-container {{
            max-width: 1000px;
        }}

        .auth-form {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        .password-form {{
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }}

        .password-form input {{
            padding: 0.4rem;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background-color: var(--bg-color);
            color: var(--text-color);
            font-size: 0.8rem;
            min-width: 120px;
        }}

        .form-group {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}

        .checkbox-group {{
            flex-direction: row;
            align-items: center;
        }}

        .form-group label {{
            font-weight: 500;
        }}

        .form-group input {{
            padding: 0.75rem;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background-color: var(--bg-color);
            color: var(--text-color);
        }}

        .error-message {{
            background-color: #fee2e2;
            color: #dc2626;
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 1rem;
        }}

        .success-message {{
            background-color: #d1fae5;
            color: #065f46;
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 1rem;
        }}

        .login-info {{
            margin-top: 1.5rem;
            padding: 1rem;
            background-color: var(--bg-color);
            border-radius: 6px;
            border-left: 4px solid var(--accent-color);
        }}

        .login-info code {{
            background-color: var(--card-bg);
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: monospace;
        }}

        .series-grid, .chapters-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1.5rem;
        }}

        .progress-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1.5rem;
        }}

        .card {{
            background-color: var(--card-bg);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 8px 12px rgba(0, 0, 0, 0.15);
        }}

        .card img {{
            width: 100%;
            height: 250px;
            object-fit: cover;
            border-bottom: 1px solid var(--border-color);
        }}

        .card-content {{
            padding: 1rem;
        }}

        .card-content h3 {{
            margin-bottom: 0.5rem;
            font-size: 1.1rem;
        }}

        .card-content p {{
            color: #666;
            font-size: 0.9rem;
        }}

        [data-theme="dark"] .card-content p {{
            color: #aaa;
        }}

        a {{
            text-decoration: none;
            color: inherit;
        }}

        .reader {{
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1.5rem;
            margin: 1rem 0;
        }}

        .manga-page {{
            max-width: 100%;
            border-radius: 12px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
            background-color: var(--card-bg);
            padding: 0.5rem;
        }}

        .current-page {{
            border: 2px solid var(--accent-color);
        }}

        .chapter-nav {{
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin: 1rem auto;
            max-width: 1200px;
            padding: 0 1rem;
            flex-wrap: wrap;
        }}

        .nav-button {{
            background-color: var(--accent-color);
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 500;
            transition: background-color 0.2s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .nav-button:hover {{
            background-color: #7c3aed;
        }}

        .nav-button.disabled {{i
            background-color: #ccc;
            cursor: not-allowed;
            opacity: 0.7;
        }}

        .series-button {{
            background-color: #6b7280;
        }}

        .series-button:hover {{
            background-color: #4b5563;
        }}

        .progress-bar {{
            width: 100%;
            height: 6px;
            background-color: var(--border-color);
            border-radius: 3px;
            overflow: hidden;
            margin: 0.5rem 0;
        }}

        .progress-bar.small {{
            height: 4px;
        }}

        .progress-fill {{
            height: 100%;
            background-color: var(--accent-color);
            transition: width 0.3s ease;
        }}

        .progress-text {{
            font-size: 0.8rem;
            color: #666;
            text-align: center;
        }}

        [data-theme="dark"] .progress-text {{
            color: #aaa;
        }}

        .chapter-status {{
            font-size: 0.8rem;
            color: #059669;
            font-weight: 500;
        }}

        .progress-tracker {{
            margin-top: 1rem;
            padding: 1rem;
            background-color: var(--card-bg);
            border-radius: 6px;
        }}

        .progress-tracker label {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            cursor: pointer;
        }}

        .continue-reading {{
            margin-bottom: 2rem;
        }}

        .continue-reading h2 {{
            margin-bottom: 1rem;
        }}

        .no-progress {{
            grid-column: 1 / -1;
            text-align: center;
            padding: 2rem;
            color: #666;
        }}

        .chapter-progress {{
            font-size: 0.8rem;
            color: #666;
            margin-top: 0.25rem;
        }}

        .create-user-section, .users-section {{
            margin-bottom: 2rem;
            padding: 1.5rem;
            background-color: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}

        .table-container {{
            overflow-x: auto;
        }}

        .users-table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--card-bg);
        }}

        .users-table th,
        .users-table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .users-table th {{
            background-color: var(--bg-color);
            font-weight: 600;
        }}

        .actions-cell {{
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }}

        .admin-badge {{
            background-color: var(--accent-color);
            color: white;
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.7rem;
            margin-left: 0.5rem;
        }}

        @media (max-width: 768px) {{
            .series-grid, .chapters-grid {{
                grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            }}
            
            header {{
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }}
            
            .chapter-nav {{
                flex-direction: column;
                align-items: center;
            }}
            
            .nav-button {{
                width: 100%;
                justify-content: center;
            }}
            
            .user-actions {{
                flex-direction: column;
                width: 100%;
            }}
            
            .button {{
                width: 100%;
                text-align: center;
            }}
            
            .actions-cell {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .password-form {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .password-form input {{
                width: 100%;
                margin-bottom: 0.5rem;
            }}
        }}
        """
        return base_css

    def get_js(self):
        """Return the JavaScript for the site"""
        return """
        // Theme toggle functionality
        document.addEventListener('DOMContentLoaded', function() {
            const themeToggle = document.getElementById('theme-toggle');
            const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
            
            // Get current theme from localStorage or prefer system preference
            const currentTheme = localStorage.getItem('theme') || 
                                (prefersDarkScheme.matches ? 'dark' : 'light');
            
            // Apply the theme
            if (currentTheme === 'dark') {
                document.body.setAttribute('data-theme', 'dark');
            } else {
                document.body.removeAttribute('data-theme');
            }
            
            // Toggle theme on button click
            themeToggle.addEventListener('click', function() {
                const currentTheme = document.body.getAttribute('data-theme');
                if (currentTheme === 'dark') {
                    document.body.removeAttribute('data-theme');
                    localStorage.setItem('theme', 'light');
                } else {
                    document.body.setAttribute('data-theme', 'dark');
                    localStorage.setItem('theme', 'dark');
                }
            });
            
            // Keyboard navigation for chapters
            document.addEventListener('keydown', function(e) {
                const prevButton = document.querySelector('.prev-button');
                const nextButton = document.querySelector('.next-button');
                
                if (e.key === 'ArrowLeft' && prevButton) {
                    prevButton.click();
                } else if (e.key === 'ArrowRight' && nextButton) {
                    nextButton.click();
                }
            });
        });
        """

def main():
    # Check if manga directory exists
    if not os.path.exists(MANGA_DIR):
        logging.error(f"Manga directory '{MANGA_DIR}' not found!")
        sys.exit(1)
    
    # Create and start the server
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, MangaRequestHandler)
    
    logging.info(f"Starting manga server on http://{HOST}:{PORT}")
    logging.info("Default admin account: username='admin', password='admin'")
    logging.info("Press Ctrl+C to stop the server")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down server")
        httpd.shutdown()

if __name__ == "__main__":
    main()