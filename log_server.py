#!/usr/bin/env python3
import socket
import threading
import json
import csv
import os

LOG_HOST = '127.0.0.1'
LOG_PORT = 9999
JSON_LOG_FILE = 'security_events.jsonl'
CSV_LOG_FILE = 'security_events.csv'
CSV_HEADERS = ['timestamp', 'event_time_iso', 'action', 'src_ip', 'dst_ip', 'dst_port', 'reason', 'duration_sec', 'response_time_ms']
file_lock = threading.Lock()

def init_csv():
    if not os.path.exists(CSV_LOG_FILE):
        with open(CSV_LOG_FILE, 'w', newline='') as f:
            csv.writer(f).writerow(CSV_HEADERS)

def record_event(ev):
    with file_lock:
        with open(JSON_LOG_FILE, 'a') as jf:
            jf.write(json.dumps(ev) + '\n')
        with open(CSV_LOG_FILE, 'a', newline='') as cf:
            csv.writer(cf).writerow([ev.get(k, '') for k in CSV_HEADERS])

    print(f"[{ev.get('event_time_iso','')}] [{ev.get('action',''):7s}] {ev.get('src_ip',''):10s} -> {ev.get('dst_ip',''):10s}:{str(ev.get('dst_port','')):5s} | Dur={ev.get('duration_sec',0):2d}s | Resp={ev.get('response_time_ms',0.0):5.2f}ms | {ev.get('reason','')}", flush=True)

def handle_conn(conn):
    buf = ""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk: break
            buf += chunk.decode('utf-8', errors='ignore')
            while '\n' in buf:
                line, buf = buf.split('\n', 1)
                if line.strip(): record_event(json.loads(line.strip()))
    finally:
        conn.close()

def start_log_server():
    init_csv()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LOG_HOST, LOG_PORT))
    srv.listen(10)
    print(f"[*] Centralized Security Event Logger listening on {LOG_HOST}:{LOG_PORT}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()

if __name__ == '__main__':
    start_log_server()
