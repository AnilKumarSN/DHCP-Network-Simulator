#!/usr/bin/env python3

import argparse
import logging
import os
import signal
import socket
import struct
import sys
import time
import select # Make sure select is imported

# Basic DHCP constants (can be expanded)
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCPV6_SERVER_PORT = 547 # Server/Relay Agent port (where clients send to relays/servers)
DHCPV6_CLIENT_PORT = 546 # Client port (where servers/relays send to clients)

# Operation codes (DHCPv4)
BOOTREQUEST = 1
BOOTREPLY = 2

# DHCP Message Types (Option 53 for DHCPv4)
DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

# DHCPv6 Message Types ( direttamente il primo byte del messaggio )
DHCPV6_SOLICIT = 1
DHCPV6_ADVERTISE = 2
DHCPV6_REQUEST = 3
DHCPV6_CONFIRM = 4
DHCPV6_RENEW = 5
DHCPV6_REBIND = 6
DHCPV6_REPLY = 7
DHCPV6_RELEASE = 8
DHCPV6_DECLINE = 9
DHCPV6_RECONFIGURE = 10
DHCPV6_INFORMATION_REQUEST = 11
DHCPV6_RELAY_FORW = 12
DHCPV6_RELAY_REPL = 13

LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

class DHCPRelayAgent:
    def __init__(self, args):
        self.args = args
        self.logger = None
        self.pidfile_path = args.pid_file
        self.running = True

        self.setup_logging()

        self.sock_v4_client = None
        self.sock_v4_server = None
        self.sock_v6_client = None
        self.sock_v6_server = None

        self.pending_transactions_v4 = {}
        self.pending_transactions_v6 = {}

    # DHCP Option codes (common subset)
    DHCP_OPTION_PAD = 0
    DHCP_OPTION_SUBNET_MASK = 1
    DHCP_OPTION_ROUTER = 3
    DHCP_OPTION_DNS_SERVER = 6
    DHCP_OPTION_HOSTNAME = 12
    DHCP_OPTION_REQUESTED_IP = 50 # DHCPv4
    DHCP_OPTION_LEASE_TIME = 51   # DHCPv4
    DHCP_OPTION_MESSAGE_TYPE = 53 # DHCPv4
    DHCP_OPTION_SERVER_ID = 54    # DHCPv4
    DHCP_OPTION_PARAM_REQUEST_LIST = 55 # DHCPv4
    DHCP_OPTION_RELAY_AGENT_INFO = 82 # Option 82 for DHCPv4
    DHCP_OPTION_END = 255

    # DHCPv6 Option codes
    DHCPV6_OPTION_CLIENTID = 1
    DHCPV6_OPTION_SERVERID = 2
    DHCPV6_OPTION_IA_NA = 3
    DHCPV6_OPTION_IA_TA = 4
    DHCPV6_OPTION_IAADDR = 5
    DHCPV6_OPTION_ORO = 6
    DHCPV6_OPTION_PREFERENCE = 7
    DHCPV6_OPTION_ELAPSED_TIME = 8
    DHCPV6_OPTION_RELAY_MSG = 9
    DHCPV6_OPTION_STATUS_CODE = 13
    DHCPV6_OPTION_USER_CLASS = 15
    DHCPV6_OPTION_VENDOR_CLASS = 16
    DHCPV6_OPTION_INTERFACE_ID = 18
    DHCPV6_OPTION_IA_PD = 25
    DHCPV6_OPTION_IAPREFIX = 26


    # Option 82 Sub-option codes
    AGENT_CIRCUIT_ID_SUBOPTION = 1
    AGENT_REMOTE_ID_SUBOPTION = 2

    def setup_logging(self):
        self.logger = logging.getLogger("DHCPRelayAgent")
        self.logger.setLevel(LOG_LEVELS.get(self.args.log_level.lower(), logging.INFO))
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        if self.args.log_file:
            log_dir = os.path.dirname(self.args.log_file)
            if log_dir and not os.path.exists(log_dir):
                try: os.makedirs(log_dir, exist_ok=True)
                except OSError as e: sys.stderr.write(f"Error creating log directory {log_dir}: {e}\n")
            try:
                file_handler = logging.FileHandler(self.args.log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except IOError as e: sys.stderr.write(f"Error opening log file {self.args.log_file}: {e}\n")

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)
        self.logger.info("Logging initialized.")

    def write_pidfile(self):
        try:
            pid = os.getpid()
            pid_dir = os.path.dirname(self.pidfile_path)
            if pid_dir and not os.path.exists(pid_dir): os.makedirs(pid_dir, exist_ok=True)
            with open(self.pidfile_path, 'w') as f: f.write(str(pid))
            self.logger.info(f"PID file {self.pidfile_path} created with PID {pid}.")
        except IOError as e:
            self.logger.error(f"Unable to write PID file {self.pidfile_path}: {e}")
            sys.exit(1)

    def remove_pidfile(self):
        try:
            if os.path.exists(self.pidfile_path):
                os.remove(self.pidfile_path)
                self.logger.info(f"PID file {self.pidfile_path} removed.")
        except IOError as e: self.logger.warning(f"Unable to remove PID file {self.pidfile_path}: {e}")

    def daemonize(self):
        if not self.args.foreground:
            self.logger.info("Daemonizing process...")
            try:
                if os.fork() > 0: sys.exit(0)
            except OSError as e: self.logger.error(f"fork #1 failed: {e.errno} ({e.strerror})"); sys.exit(1)
            os.chdir("/"); os.setsid(); os.umask(0)
            try:
                if os.fork() > 0: sys.exit(0)
            except OSError as e: self.logger.error(f"fork #2 failed: {e.errno} ({e.strerror})"); sys.exit(1)
            self.logger.info("Successfully daemonized.")
            sys.stdout.flush(); sys.stderr.flush()
            si = open(os.devnull, 'r'); so = open(os.devnull, 'a+'); se = open(os.devnull, 'a+')
            os.dup2(si.fileno(), sys.stdin.fileno()); os.dup2(so.fileno(), sys.stdout.fileno()); os.dup2(se.fileno(), sys.stderr.fileno())
        else: self.logger.info("Running in foreground.")

    def signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}. Shutting down...")
        self.running = False

    def setup_sockets_v4(self):
        self.logger.info("Setting up DHCPv4 sockets...")
        try:
            self.sock_v4_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_v4_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_v4_client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock_v4_client.bind(('', DHCP_CLIENT_PORT))
            self.logger.info(f"DHCPv4 client listening socket bound to port {DHCP_CLIENT_PORT}")

            self.sock_v4_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_v4_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.logger.info("DHCPv4 server communication socket created.")
            return True
        except OSError as e:
            self.logger.error(f"Error setting up DHCPv4 sockets: {e}")
            if self.sock_v4_client: self.sock_v4_client.close(); self.sock_v4_client = None
            return False

    def setup_sockets_v6(self):
        if not self.args.target_dhcpv6_server or not self.args.link_address_v6:
            self.logger.info("DHCPv6 target server or link-address not configured. Skipping DHCPv6 socket setup.")
            return False

        self.logger.info("Setting up DHCPv6 sockets...")
        try:
            self.sock_v6_client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_v6_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            iface_index = 0
            if self.args.client_iface:
                try: iface_index = socket.if_nametoindex(self.args.client_iface)
                except OSError as e: self.logger.error(f"Cannot get index for iface {self.args.client_iface}: {e}. Multicast join may fail or be on wrong iface."); # Proceed but warn

            self.sock_v6_client.bind(('', DHCPV6_SERVER_PORT)) # Listen on :: for server/relay port
            self.logger.info(f"DHCPv6 client listening socket bound to [::]:{DHCPV6_SERVER_PORT}")

            if iface_index != 0:
                # ff02::1:2 is All_DHCP_Relay_Agents_and_Servers (link-local)
                mreq = socket.inet_pton(socket.AF_INET6, "ff02::1:2") + struct.pack("I", iface_index)
                self.sock_v6_client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
                self.logger.info(f"Joined DHCPv6 multicast group ff02::1:2 on interface {self.args.client_iface} (index {iface_index})")
            else:
                self.logger.warning(f"Could not determine interface index for {self.args.client_iface}. Multicast group not joined. Relay may not receive all client messages.")

            self.sock_v6_server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_v6_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.logger.info("DHCPv6 server communication socket created.")
            return True
        except OSError as e:
            self.logger.error(f"Error setting up DHCPv6 sockets: {e}")
            if self.sock_v6_client: self.sock_v6_client.close(); self.sock_v6_client = None
            if self.sock_v6_server: self.sock_v6_server.close(); self.sock_v6_server = None
            return False

    def parse_dhcpv4_options(self, options_data):
        options = {}; i = 0
        while i < len(options_data):
            option_code = options_data[i]; i += 1
            if option_code == self.DHCP_OPTION_PAD: continue
            if option_code == self.DHCP_OPTION_END: break
            if i >= len(options_data): self.logger.warning("Malformed options: missing length."); break
            option_len = options_data[i]; i += 1
            if i + option_len > len(options_data): self.logger.warning(f"Opt {option_code}: val shorter than len {option_len}."); break
            options[option_code] = options_data[i:i + option_len]; i += option_len
        return options

    def parse_dhcpv4_packet(self, data):
        if len(data) < 240: self.logger.warning(f"Packet too short for DHCPv4: {len(data)}B"); return None
        header_format = '!BBBB I HH IIII 16s 64s 128s'
        try:
            op, htype, hlen, hops, xid, secs, flags, ciaddr_raw, yiaddr_raw, siaddr_raw, giaddr_raw, chaddr, sname, file_ = struct.unpack(header_format, data[:236])
            if data[236:240] != b'\x63\x82\x53\x63': self.logger.warning("Invalid DHCP magic cookie."); return None
            options = self.parse_dhcpv4_options(data[240:])
            return {'op': op, 'htype': htype, 'hlen': hlen, 'hops': hops, 'xid': xid, 'secs': secs, 'flags': flags,
                    'ciaddr': socket.inet_ntoa(ciaddr_raw), 'yiaddr': socket.inet_ntoa(yiaddr_raw),
                    'siaddr': socket.inet_ntoa(siaddr_raw), 'giaddr': socket.inet_ntoa(giaddr_raw),
                    'chaddr': chaddr[:hlen], 'sname': sname.split(b'\x00', 1)[0],
                    'file': file_.split(b'\x00', 1)[0], 'options': options, 'raw_options': data[240:]}
        except Exception as e: self.logger.error(f"Error unpacking/parsing DHCPv4: {e}"); return None

    def add_option82(self, current_options_data, circuit_id_str, remote_id_str=None):
        options = bytearray(current_options_data)
        while len(options) > 0 and options[-1] == self.DHCP_OPTION_PAD: options = options[:-1]
        if len(options) > 0 and options[-1] == self.DHCP_OPTION_END: options = options[:-1]
        opt82_payload = bytearray()
        if circuit_id_str:
            cid_bytes = circuit_id_str.encode('ascii')
            opt82_payload.extend([self.AGENT_CIRCUIT_ID_SUBOPTION, len(cid_bytes)])
            opt82_payload.extend(cid_bytes)
        if remote_id_str: # Not used in this iteration, but structure is here
            rid_bytes = remote_id_str.encode('ascii')
            opt82_payload.extend([self.AGENT_REMOTE_ID_SUBOPTION, len(rid_bytes)])
            opt82_payload.extend(rid_bytes)
        if not opt82_payload: return bytes(options) + bytes([self.DHCP_OPTION_END])
        options.extend([self.DHCP_OPTION_RELAY_AGENT_INFO, len(opt82_payload)])
        options.extend(opt82_payload)
        options.append(self.DHCP_OPTION_END)
        self.logger.debug(f"Added Option 82 (Circuit: {circuit_id_str}, Remote: {remote_id_str}). New options len: {len(options)}")
        return bytes(options)

    def strip_option82(self, options_data):
        new_options_list = bytearray()
        i = 0; original_options = bytes(options_data)
        while i < len(original_options):
            code = original_options[i]
            if code == self.DHCP_OPTION_PAD: new_options_list.append(code); i += 1; continue
            if code == self.DHCP_OPTION_END: break
            length = original_options[i+1]
            if code != self.DHCP_OPTION_RELAY_AGENT_INFO:
                new_options_list.extend(original_options[i : i + 2 + length])
            else: self.logger.info("Stripped Option 82 from server reply.")
            i += (2 + length)
        new_options_list.append(self.DHCP_OPTION_END)
        return bytes(new_options_list)

    def modify_discover_for_server(self, original_packet_data, giaddr_ip_str, current_hops):
        if len(original_packet_data) < 236: self.logger.error("Packet too short to modify."); return None
        modified_packet = bytearray(original_packet_data)
        try:
            struct.pack_into('!4s', modified_packet, 24, socket.inet_aton(giaddr_ip_str)) # giaddr @ offset 24
            self.logger.debug(f"giaddr set to {giaddr_ip_str}")
            new_hops = (current_hops + 1) % 256
            struct.pack_into('!B', modified_packet, 3, new_hops) # hops @ offset 3
            self.logger.debug(f"Hops incremented from {current_hops} to {new_hops}")
            return bytes(modified_packet)
        except socket.error as e: self.logger.error(f"Invalid giaddr IP {giaddr_ip_str}: {e}"); return None
        except struct.error as e: self.logger.error(f"Struct error modifying packet: {e}"); return None

    def handle_dhcpv4_from_client(self, data, client_addr_on_lan):
        self.logger.info(f"Received DHCPv4 packet from client network segment (source: {client_addr_on_lan}), {len(data)} bytes.")
        parsed_packet = self.parse_dhcpv4_packet(data)
        if not parsed_packet: self.logger.warning("Failed to parse DHCPv4 from client."); return
        self.logger.debug(f"Parsed client DHCPv4: {parsed_packet}")

        msg_type_opt = parsed_packet['options'].get(self.DHCP_OPTION_MESSAGE_TYPE)
        if not msg_type_opt or len(msg_type_opt) != 1: self.logger.warning("Msg Type opt missing/malformed."); return
        dhcp_msg_type = msg_type_opt[0]
        self.logger.info(f"Client DHCP Message Type: {dhcp_msg_type}")

        if parsed_packet['op'] == BOOTREQUEST and dhcp_msg_type in [DHCPDISCOVER, DHCPREQUEST]: # Handle both
            self.logger.info(f"Processing DHCPv4 {('DISCOVER' if dhcp_msg_type == DHCPDISCOVER else 'REQUEST')} from chaddr: {parsed_packet['chaddr'].hex()}")

            self.pending_transactions_v4[parsed_packet['xid']] = {'chaddr': parsed_packet['chaddr'], 'client_addr': client_addr_on_lan, 'timestamp': time.time()}
            self.logger.debug(f"Stored v4 transaction {parsed_packet['xid']} for chaddr {parsed_packet['chaddr'].hex()}")

            circuit_id_to_add = None; client_mac_str = parsed_packet['chaddr'].hex(':')
            if client_mac_str.startswith("00:aa:01"): circuit_id_to_add = "VIDEO_CIRCUIT"
            elif client_mac_str.startswith("00:aa:02"): circuit_id_to_add = "DATA_CIRCUIT"

            header_and_magic = data[:240]
            options_part = parsed_packet['raw_options'] # Use raw options from parser

            if circuit_id_to_add:
                self.logger.info(f"Policy: Adding Opt82 CircuitID={circuit_id_to_add}")
                options_part = self.add_option82(options_part, circuit_id_to_add)

            packet_with_opt82 = header_and_magic + options_part
            modified_data = self.modify_discover_for_server(packet_with_opt82, self.args.giaddr, parsed_packet['hops'])

            if not modified_data:
                self.logger.error("Failed to modify packet for server.");
                if parsed_packet['xid'] in self.pending_transactions_v4: del self.pending_transactions_v4[parsed_packet['xid']]
                return

            if self.args.target_dhcpv4_server:
                self.logger.info(f"Relaying to server {self.args.target_dhcpv4_server} (giaddr: {self.args.giaddr})")
                try: self.sock_v4_server.sendto(modified_data, (self.args.target_dhcpv4_server, DHCP_SERVER_PORT))
                except Exception as e:
                    self.logger.error(f"Error sending to v4 server: {e}");
                    if parsed_packet['xid'] in self.pending_transactions_v4: del self.pending_transactions_v4[parsed_packet['xid']]
            else:
                self.logger.warning("No target DHCPv4 server.");
                if parsed_packet['xid'] in self.pending_transactions_v4: del self.pending_transactions_v4[parsed_packet['xid']]
        else:
            self.logger.info(f"Ignoring DHCPv4 packet (type: {dhcp_msg_type}, op: {parsed_packet['op']}).")

    def handle_dhcpv4_from_server(self, data, server_addr):
        self.logger.info(f"Received DHCPv4 packet from server {server_addr}, {len(data)} bytes.")
        parsed_packet = self.parse_dhcpv4_packet(data)
        if not parsed_packet: self.logger.warning("Failed to parse DHCPv4 from server."); return
        self.logger.debug(f"Parsed server DHCPv4: {parsed_packet}")

        msg_type_opt = parsed_packet['options'].get(self.DHCP_OPTION_MESSAGE_TYPE)
        if not msg_type_opt or len(msg_type_opt) != 1: self.logger.warning("Server Msg Type opt missing/malformed."); return
        dhcp_msg_type = msg_type_opt[0]
        self.logger.info(f"Server DHCP Message Type: {dhcp_msg_type}")

        transaction_info = self.pending_transactions_v4.get(parsed_packet['xid'])
        if not transaction_info: self.logger.warning(f"Rcvd for unknown xid {parsed_packet['xid']}. Dropping."); return

        if parsed_packet['op'] == BOOTREPLY and dhcp_msg_type in [DHCPOFFER, DHCPACK]:
            self.logger.info(f"Processing {('DHCPOFFER' if dhcp_msg_type == DHCPOFFER else 'DHCPACK')} for xid: {parsed_packet['xid']}, yiaddr: {parsed_packet['yiaddr']}")

            header_and_magic = data[:240]
            options_part = parsed_packet['raw_options']
            stripped_options_part = self.strip_option82(options_part)
            packet_for_client = header_and_magic + stripped_options_part

            dest_addr_client_segment = ('255.255.255.255', DHCP_CLIENT_PORT)
            self.logger.info(f"Relaying to client segment for chaddr {transaction_info['chaddr'].hex()}")
            try: self.sock_v4_client.sendto(packet_for_client, dest_addr_client_segment)
            except Exception as e: self.logger.error(f"Error relaying to client: {e}")

            if dhcp_msg_type == DHCPACK: # Transaction complete
                if parsed_packet['xid'] in self.pending_transactions_v4:
                    del self.pending_transactions_v4[parsed_packet['xid']]
                    self.logger.debug(f"V4 Transaction {parsed_packet['xid']} completed and removed.")
        else:
            self.logger.info(f"Ignoring other DHCPv4 from server (type: {dhcp_msg_type}, op: {parsed_packet['op']}).")

    # Placeholder for DHCPv6 handlers
    def handle_dhcpv6_from_client(self, data, client_addr_info):
        self.logger.info(f"Received DHCPv6 data from {client_addr_info}, {len(data)} bytes. Handling not yet implemented.")

    def handle_dhcpv6_from_server(self, data, server_addr_info):
        self.logger.info(f"Received DHCPv6 data from {server_addr_info}, {len(data)} bytes. Handling not yet implemented.")

    def run(self):
        if not self.args.foreground: self.daemonize()
        self.write_pidfile()
        signal.signal(signal.SIGINT, self.signal_handler); signal.signal(signal.SIGTERM, self.signal_handler)

        v4_sockets_ok = self.setup_sockets_v4()
        v6_sockets_ok = self.setup_sockets_v6()

        self.logger.info("Python DHCP Relay Agent started.")
        self.logger.info(f"Client-facing interface: {self.args.client_iface} (intended for binding/multicast)")
        self.logger.info(f"Server-facing interface: {self.args.server_iface} (intended for routing)")

        inputs = []
        if v4_sockets_ok and self.sock_v4_client: inputs.append(self.sock_v4_client)
        if v4_sockets_ok and self.sock_v4_server: inputs.append(self.sock_v4_server)
        if v6_sockets_ok and self.sock_v6_client: inputs.append(self.sock_v6_client)
        if v6_sockets_ok and self.sock_v6_server: inputs.append(self.sock_v6_server)

        if not inputs: self.logger.error("No sockets initialized. Exiting."); return
        self.logger.info(f"Starting main select loop, monitoring {len(inputs)} sockets...")

        while self.running:
            try:
                self.logger.debug(f"select() waiting on {len(inputs)} sockets...")
                readable, _, exceptional = select.select(inputs, [], inputs, 1.0)
                if not self.running: break

                for s in readable:
                    if not self.running: break
                    if s is self.sock_v4_client:
                        data, addr = s.recvfrom(1024)
                        self.handle_dhcpv4_from_client(data, addr)
                    elif s is self.sock_v4_server:
                        data, addr = s.recvfrom(1024)
                        self.handle_dhcpv4_from_server(data, addr)
                    elif s is self.sock_v6_client:
                        data, addr = s.recvfrom(2048)
                        self.handle_dhcpv6_from_client(data, addr)
                    elif s is self.sock_v6_server:
                        data, addr = s.recvfrom(2048)
                        self.handle_dhcpv6_from_server(data, addr)

                for s in exceptional:
                    self.logger.error(f"Exceptional condition on socket {s.fileno()}")
                    if s in inputs: inputs.remove(s)
                    # For robustnes, might try to re-init the failing socket. For now, if a socket fails, it's removed.
                    # If all sockets fail, inputs will be empty and loop might spin.
                    if not inputs : self.running = False; self.logger.error("All monitored sockets failed.")
            except KeyboardInterrupt: self.logger.info("KeyboardInterrupt in run loop."); self.running = False
            except select.error as e: self.logger.error(f"select.error: {e}"); time.sleep(0.1)
            except Exception as e: self.logger.error(f"Error in main loop: {e}", exc_info=True); time.sleep(0.1)

        self.logger.info("Shutting down relay agent...")
        for sock in [self.sock_v4_client, self.sock_v4_server, self.sock_v6_client, self.sock_v6_server]:
            if sock: sock.close()
        self.remove_pidfile()
        self.logger.info("Python DHCP Relay Agent stopped.")

def main():
    parser = argparse.ArgumentParser(description="Python DHCP Relay Agent")
    parser.add_argument('--client-iface', required=True, help="Client-facing network interface name (e.g., v_pyrelay_c_ns).")
    parser.add_argument('--server-iface', required=True, help="Server-facing network interface name (e.g., v_pyrelay_s_ns).")

    parser.add_argument('--target-dhcpv4-server', required=True, help="IP address of the target Kea DHCPv4 server.")
    parser.add_argument('--giaddr', required=True, help="Gateway IP Address (giaddr) to set in relayed DHCPv4 packets.")

    parser.add_argument('--target-dhcpv6-server', help="IP address of the target Kea DHCPv6 server (e.g., fd00:red::1).")
    parser.add_argument('--link-address-v6', help="IPv6 Link Address for Relay-Forward (e.g., fd00:red::fe, an IP on client-facing iface).")

    parser.add_argument('--pid-file', required=True, help="Path to PID file.")
    parser.add_argument('--log-file', help="Path to log file. If not specified, logs to stdout/stderr based on foreground mode.")
    parser.add_argument('--log-level', default='info', choices=LOG_LEVELS.keys(), help="Logging level.")
    parser.add_argument('-f', '--foreground', action='store_true', help="Run in foreground (do not daemonize).")

    args = parser.parse_args()
    relay_agent = DHCPRelayAgent(args)
    try: relay_agent.run()
    except KeyboardInterrupt: print("Ctrl+C received, shutting down relay agent..."); relay_agent.running = False
    except Exception as e:
        logger_to_use = relay_agent.logger if hasattr(relay_agent, 'logger') and relay_agent.logger else logging.getLogger()
        logger_to_use.critical(f"Unhandled exception: {e}", exc_info=True)
    finally:
        if hasattr(relay_agent, 'pidfile_path') and relay_agent.pidfile_path and os.path.exists(relay_agent.pidfile_path):
             # Check if current process owns the pid before removing
             try:
                 with open(relay_agent.pidfile_path, 'r') as pf:
                     pid_in_file = pf.read().strip()
                 if pid_in_file == str(os.getpid()):
                     relay_agent.remove_pidfile()
                 else:
                    if hasattr(relay_agent, 'logger') and relay_agent.logger:
                         relay_agent.logger.warning(f"PID file {relay_agent.pidfile_path} owned by another process ({pid_in_file}). Not removing.")
                    else: # logger might not be init if error was too early
                         print(f"Warning: PID file {relay_agent.pidfile_path} owned by another process ({pid_in_file}). Not removing.", file=sys.stderr)

             except Exception as e_pid: # Broad catch for issues reading/checking PID file during final cleanup
                 if hasattr(relay_agent, 'logger') and relay_agent.logger:
                    relay_agent.logger.error(f"Error during final PID file check/removal: {e_pid}")
                 else:
                    print(f"Error during final PID file check/removal: {e_pid}", file=sys.stderr)


if __name__ == '__main__':
    main()
