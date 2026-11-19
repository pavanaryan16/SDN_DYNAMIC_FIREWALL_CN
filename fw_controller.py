import os, sys; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
#!/usr/bin/env python3
import json
import socket
import time
import datetime
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, arp, icmp, ether_types

from detector import AnomalyDetector

POLICY_FILE = 'policy.json'
LOG_SERVER_IP = '127.0.0.1'
LOG_SERVER_PORT = 9999
BLOCK_COOKIE_BASE = 0xABCD0000

class DynamicFirewallController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicFirewallController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.cookie_to_ip = {}
        self.cookie_counter = 1
        self.policy = self._load_policy()

        thresh = self.policy.get('detection_thresholds', {})
        timeouts = self.policy.get('timeouts', {})
        self.detector = AnomalyDetector(
            window_sec=thresh.get('window_seconds', 5.0),
            scan_port_threshold=thresh.get('port_scan_distinct_ports', 6),
            flood_conn_threshold=thresh.get('conn_flood_max_connections', 10),
            base_block_sec=timeouts.get('base_block_hard_timeout', 15)
        )

    def _load_policy(self):
        try:
            with open(POLICY_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {
                "allowed_tcp_ports": [8080, 5001],
                "forbidden_tcp_ports": [21, 23, 445],
                "timeouts": {"allow_idle_timeout": 30, "deny_idle_timeout": 30, "base_block_hard_timeout": 15}
            }

    def send_log_event(self, action, src_ip, dst_ip, dst_port, reason, duration_sec=0, response_time_ms=0.0):
        event = {
            "timestamp": round(time.time(), 4),
            "event_time_iso": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "action": action,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "reason": reason,
            "duration_sec": duration_sec,
            "response_time_ms": round(response_time_ms, 3)
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((LOG_SERVER_IP, LOG_SERVER_PORT))
            s.sendall((json.dumps(event) + "\n").encode('utf-8'))
            s.close()
        except Exception as e:
            self.logger.warning(f"[LOG WARN] Centralized logger unreachable: {e}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info(f"[SWITCH] Switch s1 (DPID={datapath.id}) connected. Table-miss rule installed.")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, cookie=0, send_flow_rem=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flags = ofproto.OFPFF_SEND_FLOW_REM if send_flow_rem else 0
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=cookie, priority=priority,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
            flags=flags, match=match, instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        cookie = msg.cookie
        if cookie in self.cookie_to_ip:
            recovered_ip = self.cookie_to_ip.pop(cookie)
            self.detector.clear_block_state(recovered_ip)
            self.logger.info(f"[AUTOMATIC RECOVERY] Block rule expired for host {recovered_ip}. Host is now UNBLOCKED.")
            self.send_log_event("RECOVER", recovered_ip, "ALL", "ALL", "HARD_TIMEOUT_EXPIRED_AUTOMATIC_RECOVERY", msg.duration_sec, 0.0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        t_start = time.time()
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        if eth.ethertype == ether_types.ETH_TYPE_ARP or pkt.get_protocol(icmp.icmp):
            actions = [parser.OFPActionOutput(out_port)]
            data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip_pkt and tcp_pkt:
            src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
            src_port, dst_port = tcp_pkt.src_port, tcp_pkt.dst_port

            if src_port in self.policy.get('allowed_tcp_ports', [8080]):
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=src_ip, ipv4_dst=dst_ip, tcp_src=src_port, tcp_dst=dst_port)
                self.add_flow(datapath, priority=20, match=match, actions=actions, idle_timeout=30)
                data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

            is_syn = bool(tcp_pkt.bits & tcp.TCP_SYN) and not bool(tcp_pkt.bits & tcp.TCP_ACK)
            verdict, reason, block_dur = self.detector.record_and_inspect(src_ip, dst_ip, dst_port, is_new_syn=is_syn)

            if verdict == "BLOCK":
                cookie = BLOCK_COOKIE_BASE + self.cookie_counter
                self.cookie_counter += 1
                self.cookie_to_ip[cookie] = src_ip
                block_match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                self.add_flow(datapath, priority=100, match=block_match, actions=[], hard_timeout=block_dur, cookie=cookie, send_flow_rem=True)
                resp_ms = (time.time() - t_start) * 1000.0
                self.logger.warning(f"[BLOCK] Host {src_ip} blocked for {block_dur}s | Reason: {reason}")
                self.send_log_event("BLOCK", src_ip, dst_ip, dst_port, reason, block_dur, resp_ms)
                return

            forbidden_ports = self.policy.get('forbidden_tcp_ports', [21, 23, 445])
            if dst_port in forbidden_ports or dst_port not in self.policy.get('allowed_tcp_ports', [8080, 5001]):
                deny_idle = self.policy.get('timeouts', {}).get('deny_idle_timeout', 30)
                deny_match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=src_ip, ipv4_dst=dst_ip, tcp_dst=dst_port)
                self.add_flow(datapath, priority=50, match=deny_match, actions=[], idle_timeout=deny_idle)
                resp_ms = (time.time() - t_start) * 1000.0
                self.send_log_event("DENY", src_ip, dst_ip, dst_port, f"POLICY_VIOLATION_PORT_{dst_port}_FORBIDDEN", deny_idle, resp_ms)
                return

            allow_idle = self.policy.get('timeouts', {}).get('allow_idle_timeout', 30)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                allow_match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=src_ip, ipv4_dst=dst_ip, tcp_src=src_port, tcp_dst=dst_port)
                self.add_flow(datapath, priority=20, match=allow_match, actions=actions, idle_timeout=allow_idle)

            resp_ms = (time.time() - t_start) * 1000.0
            if is_syn:
                self.send_log_event("ALLOW", src_ip, dst_ip, dst_port, "POLICY_MATCH_ALLOWED", allow_idle, resp_ms)

            data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
