#!/usr/bin/env python3
import socket
import sys
import time

SERVER_IP = '10.0.0.4'
ALLOWED_PORT = 8080
FORBIDDEN_PORT = 23

def tcp_request(dst_ip, dst_port, message, timeout=1.5):
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((dst_ip, dst_port))
        s.sendall(message.encode('utf-8'))
        resp = s.recv(1024).decode('utf-8', errors='ignore').strip()
        rtt = (time.time() - t0) * 1000.0
        s.close()
        return True, resp, rtt
    except Exception as e:
        rtt = (time.time() - t0) * 1000.0
        return False, str(e), rtt

def mode_normal(count=8):
    print(f"=== [MODE: NORMAL] Connecting to {SERVER_IP}:{ALLOWED_PORT} ===")
    for i in range(1, count + 1):
        ok, info, rtt = tcp_request(SERVER_IP, ALLOWED_PORT, f"PING_DATA_{i}")
        status = "ALLOWED" if ok else "DROPPED"
        print(f" [Req {i:02d}] Status: {status:7s} | RTT: {rtt:6.2f} ms | Info: {info}")
        time.sleep(1.0)

def mode_forbidden():
    print(f"=== [MODE: FORBIDDEN ACCESS] Connecting to Forbidden Port {FORBIDDEN_PORT} (Telnet) ===")
    for i in range(1, 4):
        ok, info, rtt = tcp_request(SERVER_IP, FORBIDDEN_PORT, "TELNET_LOGIN_ATTEMPT", timeout=1.5)
        status = "ALLOWED" if ok else "DENIED (Policy Rule)"
        print(f" [Attempt {i}] Port {FORBIDDEN_PORT} -> Status: {status} | RTT: {rtt:6.2f} ms")
        time.sleep(0.5)
    print(" -> Verifying that Port 8080 is STILL ALLOWED for this host:")
    ok, info, rtt = tcp_request(SERVER_IP, ALLOWED_PORT, "CHECK_ALLOWED_PORT_8080")
    print(f" [Check 8080] Status: {'ALLOWED' if ok else 'BLOCKED'} | Info: {info}")

def mode_port_scan():
    print(f"=== [MODE: PORT SCAN ATTACK] Probing 10 distinct ports on {SERVER_IP} in < 5s ===")
    for port in range(8001, 8011):
        ok, info, rtt = tcp_request(SERVER_IP, port, "SCAN_PROBE", timeout=0.35)
        print(f" [Scan] Probed {SERVER_IP}:{port} -> {'Open' if ok else 'Closed/Filtered'} ({rtt:.1f} ms)")
        time.sleep(0.08)

def mode_conn_flood():
    print(f"=== [MODE: CONNECTION FLOOD ATTACK] Opening 18 rapid connections to {SERVER_IP}:{ALLOWED_PORT} ===")
    for i in range(1, 19):
        ok, info, rtt = tcp_request(SERVER_IP, ALLOWED_PORT, f"FLOOD_SYN_{i}", timeout=0.4)
        status = "CONNECTED" if ok else "BLOCKED BY SDN"
        print(f" [Flood #{i:02d}] Status: {status} ({rtt:.1f} ms)")
        time.sleep(0.06)

def mode_recovery_demo():
    print("=== Phase 1: Baseline Legitimate Request ===")
    ok, info, rtt = tcp_request(SERVER_IP, ALLOWED_PORT, "BASELINE_OK")
    print(f" [Baseline] Status: {'ALLOWED' if ok else 'BLOCKED'} | {info}\n")
    time.sleep(1.0)
    print("=== Phase 2: Triggering Port Scan Attack (1st Offense -> 15s Block) ===")
    mode_port_scan()
    print("\n=== Phase 3: Monitoring Automatic Block & Automatic Recovery ===")
    t_start = time.time()
    for i in range(1, 12):
        elapsed = time.time() - t_start
        ok, info, rtt = tcp_request(SERVER_IP, ALLOWED_PORT, f"RECOVERY_PROBE_{i}", timeout=1.2)
        if not ok:
            print(f" [+{elapsed:05.2f}s] Probe {i:02d}: HOST BLOCKED AT SWITCH (Timeout)")
        else:
            print(f" [+{elapsed:05.2f}s] Probe {i:02d}: AUTOMATICALLY RECOVERED! -> {info}")
            break
        time.sleep(2.0)

if __name__ == '__main__':
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else 'normal'
    if mode == 'normal': mode_normal()
    elif mode == 'forbidden': mode_forbidden()
    elif mode == 'scan': mode_port_scan()
    elif mode == 'flood': mode_conn_flood()
    elif mode == 'recovery': mode_recovery_demo()
    else: print("Usage: python3 client.py [normal | forbidden | scan | flood | recovery]")
