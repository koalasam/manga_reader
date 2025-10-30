import os
# Configuration - use environment variables with your specific paths
MANGA_DIR = "./manga" #'/mnt/nas_share/Media/Manga'
PORT = 9008
HOST = '0.0.0.0'
DATABASE_FILE = os.getenv('DATABASE_FILE', './manga.db') #os.getenv('DATABASE_FILE', '/data/manga.db')
ACCENT_COLOR = "#8b5cf6"  # Purple accent