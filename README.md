# Manga Reader Web Server

A self-hosted manga reading web application with user accounts, reading progress tracking, and a clean, responsive interface. Perfect for organizing and reading your personal manga collection.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

## Features

- 📚 **Library Management** - Browse your manga collection with beautiful card-based interface
- 👤 **Multi-User Support** - Create multiple user accounts with individual reading progress
- 🔐 **Admin Panel** - Manage users, change passwords, and control access
- 📊 **Progress Tracking** - Automatic reading progress tracking per chapter and series
- 🌙 **Dark Mode** - Built-in light/dark theme toggle with localStorage persistence
- 📱 **Responsive Design** - Works seamlessly on desktop, tablet, and mobile devices
- ⌨️ **Keyboard Navigation** - Use arrow keys to navigate between chapters
- 🚀 **Easy Deployment** - Docker Compose ready with minimal configuration

## Screenshots

### Library View
Browse all your manga series with cover previews and progress indicators.

### Chapter Reader
Clean, distraction-free reading experience with automatic progress saving.

### Admin Panel
Manage users, create accounts, and change passwords from a simple interface.

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Manga organized in the following structure:
  ```
  /path/to/manga/
  ├── Series-Name-1/
  │   ├── Chapter-1/
  │   │   ├── page001.jpg
  │   │   ├── page002.jpg
  │   │   └── ...
  │   ├── Chapter-2/
  │   └── ...
  └── Series-Name-2/
      └── ...
  ```

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/manga-reader.git
   cd manga-reader
   ```

2. Edit `docker-compose.yml` to set your manga directory path:
   ```yaml
   volumes:
     # Update this path to your manga directory
     - /path/to/your/manga:/mnt/nas_share/Media/Manga:ro
     
     # Update this path to where you want to store the database
     - /path/to/data/directory:/mnt/nas_share/Containers/mangareader:rw
   ```

3. (Optional) Edit `config.py` to customize settings:
   ```python
   MANGA_DIR = "/mnt/nas_share/Media/Manga"
   PORT = 9008
   HOST = '0.0.0.0'
   ACCENT_COLOR = "#8b5cf6"  # Change accent color
   ```

4. Start the server:
   ```bash
   docker-compose up -d
   ```

5. Access the web interface at `http://localhost:9008`

6. Login with default credentials:
   - **Username**: `admin`
   - **Password**: `admin`
   - ⚠️ **Change this password immediately after first login!**

## Configuration

### Environment Variables

- `DATABASE_FILE` - Path to SQLite database (default: `./manga.db`)
- `TZ` - Timezone for timestamps (default: `Pacific/Auckland`)
- `PYTHONUNBUFFERED` - Python output buffering (default: `1`)

### Volume Mounts

The Docker setup requires the following volume mounts:

1. **Application Files** (read-only) - All Python modules:
   - `manager.py` - Main application entry point
   - `config.py` - Configuration settings
   - `database.py` - Database management
   - `mangarequesthandler.py` - HTTP request handler

2. **Manga Directory** (read-only) - Your manga collection

3. **Database Directory** (read-write) - Stores user data and progress

### Port Configuration

By default, the server runs on port `9008`. Change this in `docker-compose.yml`:

```yaml
ports:
  - "YOUR_PORT:9008"
```

## Usage

### Managing Users (Admin)

1. Navigate to **Admin Panel** from the top navigation
2. Create new users with optional admin privileges
3. Change user passwords or delete users as needed
4. Note: Cannot delete yourself or the last admin account

### Reading Manga

1. Click on any series from the library
2. Select a chapter to start reading
3. Scroll through pages - progress is automatically saved
4. Use keyboard arrows (← →) to navigate between chapters
5. Check "Mark as completed" to mark a chapter as finished

### Tracking Progress

- Visit **My Progress** to see all series you've started
- Progress bars show completion percentage
- "Continue Reading" section shows recently accessed series
- Progress is synced per user account

## Project Structure

```
manga-reader/
├── docker-compose.yml          # Docker configuration
├── manager.py                  # Main application entry point
├── config.py                   # Configuration settings
├── database.py                 # Database management and user authentication
├── mangarequesthandler.py      # HTTP request handler and HTML generation
├── LICENSE                     # MIT License
├── README.md                   # This file
└── data/                       # Created automatically
    └── manga.db               # SQLite database
```

## Supported Image Formats

- JPEG (.jpg, .jpeg)
- PNG (.png)

Images are served directly with proper content-type headers.

## Technical Details

### Built With

- **Python 3.11** - Core application
- **SQLite** - Database for users and progress
- **HTTP Server** - Built-in Python HTTP server
- **No external dependencies** - Pure Python implementation

### Architecture

The application is split into four main modules:

- **manager.py** - Server initialization and startup
- **config.py** - Centralized configuration
- **database.py** - Database operations, user management, and progress tracking
- **mangarequesthandler.py** - HTTP routing, HTML generation, and request handling

## Troubleshooting

### Database locked errors
The application uses WAL mode for better concurrency. If issues persist, check file permissions on the database directory.

### Images not loading
Ensure the manga directory is properly mounted and readable by the container:
```bash
docker-compose logs manga-reader
```

### Cannot access from other devices
Make sure the host is set to `0.0.0.0` (default) and firewall allows port 9008.

### Health check failing
Wait 40 seconds after starting for the health check grace period. Check logs for startup errors.

### Module import errors
Ensure all Python files are properly mounted in the docker-compose.yml and paths are correct.

## Development

### Running Without Docker

```bash
# Set environment variables
export DATABASE_FILE="./manga.db"

# Ensure config.py points to your manga directory
# Edit MANGA_DIR in config.py

# Install Python 3.11+ (no additional packages needed)

# Run the application
python3 manager.py
```

### Running Locally for Development

```bash
# Clone the repository
git clone https://github.com/yourusername/manga-reader.git
cd manga-reader

# Edit config.py to set local paths
# MANGA_DIR = "./manga"
# DATABASE_FILE = "./manga.db"

# Run the server
python3 manager.py
```

### Customization

- **Accent Color**: Change `ACCENT_COLOR` in `config.py`
- **Port**: Modify `PORT` in `config.py`
- **Database Location**: Set `DATABASE_FILE` environment variable or in `config.py`
- **Manga Directory**: Update `MANGA_DIR` in `config.py`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Roadmap

- [ ] Bookmark system
- [ ] Series metadata (description, author, genre)
- [ ] Search and filter functionality
- [ ] Reading lists/collections
- [ ] Bulk import/scan functionality
- [ ] Reading statistics and analytics

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by various manga reader applications
- Built for personal manga collection management
- Designed with simplicity and ease of use in mind

## Support

For issues, questions, or suggestions, please open an issue on GitHub.

---

**Note**: This is a self-hosted solution intended for personal use with legally obtained manga. Please respect copyright laws and support manga creators by purchasing official releases.
