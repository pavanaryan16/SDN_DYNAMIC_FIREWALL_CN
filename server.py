#!/usr/bin/env python3
import socket
import threading
import datetime
import sys

BIND_IP = '0.0.0.0'
DEFAULT_PORT = 8080
active_clients = 0
lock = threading.Lock()

def handle_client(conn, addr, port):
    global active_clients
    with lock:
        active_clients += 1
        current_load = active_clients

    src_ip, src_port = addr[0], addr[1]
    now = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    try:
        data = conn.recv(1024).decode('utf-8', errors='ignore').strip()
        if data:
            print(f"[{now}] [PORT {port}] [ACTIVE={current_load}] {src_ip}:{src_port} -> '{data}'", flush=True)
            reply = f"SERVER_ACK (Port {port}): Processed '{data}' for {src_ip}\n"
            conn.sendall(reply.encode('utf-8'))
    except Exception as e:
        print(f"[{now}] [ERROR] {src_ip}:{src_port} -> {e}", flush=True)
    finally:
        conn.close()
        with lock:
            active_clients -= 1

def start_listener(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_IP, port))
    srv.listen(50)
    print(f"[*] Multi-Threaded TCP Server listening on {BIND_IP}:{port}", flush=True)
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, port), daemon=True)
        t.start()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    start_listener(port)
