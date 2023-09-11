import http.server
import socketserver
import urllib.parse

class C2Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Process GET requests from the client
        parsed_path = urllib.parse.urlparse(self.path)
        command = parsed_path.path[1:]  # Extract the command from the URL
        response = execute_command(command)
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')
        self.send_header('X-Custom-Header', 'MyCustomValue')  # Add your custom header here
        self.end_headers()
        self.wfile.write(response.encode())

    def do_POST(self):
        # Process POST requests from the client (if needed)
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        response = execute_command(post_data.decode())
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')
        self.send_header('X-Custom-Header', 'MyCustomValue')  # Add your custom header here
        self.end_headers()
        self.wfile.write(response.encode())

def execute_command(command):
    # Add your command execution logic here
    # For example, execute the command on the target system
    return "Command executed successfully"

def run_c2_server():
    PORT = 8080  # Use the common HTTP port 80
    Handler = C2Handler
    httpd = socketserver.TCPServer(('127.0.0.1', PORT), Handler)
    print(f"Listening on port {PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    run_c2_server()
