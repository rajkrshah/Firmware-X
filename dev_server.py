"""
FirmwareX - Python Development Server
Serves both public/ and modules/ directories correctly.
"""
import http.server
import os
import sys

PORT = 3000
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

class FirmwareXHandler(http.server.SimpleHTTPRequestHandler):
    """Custom handler that maps /modules/ to ./modules/ and everything else to ./public/"""

    def translate_path(self, path):
        # Remove query strings
        path = path.split('?')[0].split('#')[0]

        if path.startswith('/modules/'):
            # Serve from project root modules/
            return os.path.join(PROJECT_ROOT, path.lstrip('/'))
        else:
            # Serve from public/
            rel = path.lstrip('/')
            if rel == '' or rel == '/':
                rel = 'index.html'
            return os.path.join(PROJECT_ROOT, 'public', rel)

    def end_headers(self):
        # CORS and cache headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache')
        super().end_headers()

    def log_message(self, format, *args):
        status = args[1] if len(args) > 1 else ''
        if '404' in str(status):
            print(f"  \033[91m✖ 404\033[0m {args[0]}")
        elif '200' in str(status):
            print(f"  \033[92m✔ 200\033[0m {args[0]}")
        else:
            print(f"  {status} {args[0]}")

if __name__ == '__main__':
    os.chdir(PROJECT_ROOT)
    
    print()
    print("  ╔═══════════════════════════════════════════════════╗")
    print("  ║        FirmwareX Development Server               ║")
    print("  ╚═══════════════════════════════════════════════════╝")
    print()
    print(f"  🌐 Web UI:  http://localhost:{PORT}")
    print(f"  📁 Root:    {PROJECT_ROOT}")
    print(f"  📦 Modules: {os.path.join(PROJECT_ROOT, 'modules')}")
    print(f"  🎨 Public:  {os.path.join(PROJECT_ROOT, 'public')}")
    print()
    print("  Press Ctrl+C to stop.")
    print()

    with http.server.HTTPServer(('', PORT), FirmwareXHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")
