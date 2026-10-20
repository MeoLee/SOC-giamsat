"""Serve one fixed benign marker to one lab peer, then exit; no file browsing."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from endpoint_probe import PAYLOAD, PAYLOAD_SHA256, SERVER_PORT, private_ipv4


def state_path(token):
    if not re.fullmatch(r'[a-f0-9]{32}', token):
        raise ValueError('Invalid server token')
    return Path('/tmp/soc-lab-transfer-'+token+'.jsonl')


def serve(token, bind, peer):
    bind, peer = private_ipv4(bind), private_ipv4(peer)
    state = state_path(token)
    with state.open('x', encoding='utf-8') as log:
        def emit(**fields):
            log.write(json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(),
                                 'probe_id': token, **fields})+'\n')
            log.flush(); os.fsync(log.fileno())
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.client_address[0] != peer or self.path != '/'+token+'.txt':
                    self.send_error(404); return
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(PAYLOAD)))
                self.end_headers(); self.wfile.write(PAYLOAD); self.wfile.flush()
                emit(kind='transfer_served', peer_ip=peer, bytes_sent=len(PAYLOAD),
                     sha256=PAYLOAD_SHA256, path=self.path)
                self.server.completed = True
            def log_message(self, *_): pass
        class BoundedServer(HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(3)
                return connection, address
        with BoundedServer((bind, SERVER_PORT), Handler) as server:
            server.timeout = 1; server.completed = False
            emit(kind='ready', pid=os.getpid(), bind=bind, port=SERVER_PORT)
            deadline = time.monotonic()+120
            while not server.completed and time.monotonic() < deadline:
                server.handle_request()
            emit(kind='closed', completed=server.completed)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--token', required=True); p.add_argument('--bind', required=True)
    p.add_argument('--peer', required=True)
    a = p.parse_args(); serve(a.token, a.bind, a.peer)


if __name__ == '__main__': main()
