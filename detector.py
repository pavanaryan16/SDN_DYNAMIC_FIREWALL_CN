#!/usr/bin/env python3
import time
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, window_sec=5.0, scan_port_threshold=6, flood_conn_threshold=10, base_block_sec=15):
        self.window_sec = window_sec
        self.scan_port_threshold = scan_port_threshold
        self.flood_conn_threshold = flood_conn_threshold
        self.base_block_sec = base_block_sec
        self.port_history = defaultdict(list)
        self.conn_history = defaultdict(list)
        self.offense_count = defaultdict(int)
        self.currently_blocked = {}

    def clear_block_state(self, src_ip):
        self.currently_blocked.pop(src_ip, None)
        self.port_history[src_ip].clear()
        self.conn_history[src_ip].clear()

    def record_and_inspect(self, src_ip, dst_ip, dst_port, is_new_syn=True):
        now = time.time()
        self.port_history[src_ip] = [(ts, p) for (ts, p) in self.port_history[src_ip] if now - ts <= self.window_sec]
        self.conn_history[src_ip] = [ts for ts in self.conn_history[src_ip] if now - ts <= self.window_sec]

        if dst_port is not None:
            self.port_history[src_ip].append((now, dst_port))
        if is_new_syn:
            self.conn_history[src_ip].append(now)

        distinct_ports = {p for (_, p) in self.port_history[src_ip]}
        if len(distinct_ports) >= self.scan_port_threshold:
            return self._trigger_block(src_ip, f"PORT_SCAN_DETECTED ({len(distinct_ports)} distinct ports in {self.window_sec}s)")

        conn_count = len(self.conn_history[src_ip])
        if conn_count >= self.flood_conn_threshold:
            return self._trigger_block(src_ip, f"CONNECTION_FLOOD_DETECTED ({conn_count} connections in {self.window_sec}s)")

        return ("OK", "NORMAL_TRAFFIC", 0)

    def _trigger_block(self, src_ip, reason):
        now = time.time()
        self.offense_count[src_ip] += 1
        offense_num = self.offense_count[src_ip]
        duration = min(self.base_block_sec * (2 ** (offense_num - 1)), 120)
        self.currently_blocked[src_ip] = now + duration
        self.port_history[src_ip].clear()
        self.conn_history[src_ip].clear()
        return ("BLOCK", f"{reason} [Offense #{offense_num} -> Escalated Block={duration}s]", duration)
