import os
import logging
import sys
from http.server import HTTPServer
from config import *
from mangarequesthandler import MangaRequestHandler

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