#!/usr/bin/env python3
import http.server
import json
import time

class MockOllamaHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        response = {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": 1,
            "model": "gemma3:1b",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "This is a mock response for testing purposes."},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60}
        }
        
        resp_body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(resp_body))
        self.end_headers()
        self.wfile.write(resp_body)
    
    def do_GET(self):
        if self.path == '/api/tags':
            response = {"models": [{"name": "gemma3:1b", "size": 806000000}]}
        else:
            response = {"status": "ok"}
        resp_body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(resp_body))
        self.end_headers()
        self.wfile.write(resp_body)
    
    def log_message(self, format, *args):
        pass  # Suppress logs

if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', 11434), MockOllamaHandler)
    print('Mock Ollama running on :11434')
    server.serve_forever()
