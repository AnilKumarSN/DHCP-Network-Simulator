#!/usr/bin/env python3

import argparse
import logging
import os
import signal
import socket
import struct
import sys
import time

# Basic DHCP constants (can be expanded)
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCPV6_SERVER_PORT = 547 # Server/Relay Agent port
DHCPV6_CLIENT_PORT = 546 # Client port

# Operation codes
BOOTREQUEST = 1
BOOTREPLY = 2

# DHCP Message Types (Option 53)
DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

# DHCPv6 Message Types
DHCPV6_SOLICIT = 1
DHCPV6_ADVERTISE = 2
DHCPV6_REQUEST = 3
# ... and so on

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

        # Sockets will be created in the run method after potential daemonization
        self.sock_v4_client = None # Listen on client-facing interface for client requests
        self.sock_v4_server = None # Send to/recv from DHCPv4 server on server-facing interface
        # TODO: Add IPv6 sockets

    def setup_logging(self):
        self.logger = logging.getLogger("DHCPRelayAgent")
        self.logger.setLevel(LOG_LEVELS.get(self.args.log_level.lower(), logging.INFO))

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        if self.args.log_file:
            # Ensure log directory exists if log_file path includes directories
            log_dir = os.path.dirname(self.args.log_file)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except OSError as e:
                    sys.stderr.write(f"Error creating log directory {log_dir}: {e}\n")
                    # Fallback to stderr or exit if critical

            try:
                file_handler = logging.FileHandler(self.args.log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except IOError as e:
                sys.stderr.write(f"Error opening log file {self.args.log_file}: {e}\n")
                # Optionally add a StreamHandler as fallback if file logging fails
                # For now, if file logging fails, messages might be lost if no other handler.

        # Always log to console if not daemonized, or if verbosity demands it
        # For simplicity now, let's always add a stream handler for visibility during development
        # This can be refined based on daemonization status later.
        stream_handler = logging.StreamHandler(sys.stdout) # Or sys.stderr
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)

        self.logger.info("Logging initialized.")

    def write_pidfile(self):
        try:
            pid = os.getpid()
            pid_dir = os.path.dirname(self.pidfile_path)
            if pid_dir and not os.path.exists(pid_dir):
                os.makedirs(pid_dir, exist_ok=True)
            with open(self.pidfile_path, 'w') as f:
                f.write(str(pid))
            self.logger.info(f"PID file {self.pidfile_path} created with PID {pid}.")
        except IOError as e:
            self.logger.error(f"Unable to write PID file {self.pidfile_path}: {e}")
            sys.exit(1)

    def remove_pidfile(self):
        try:
            if os.path.exists(self.pidfile_path):
                os.remove(self.pidfile_path)
                self.logger.info(f"PID file {self.pidfile_path} removed.")
        except IOError as e:
            self.logger.warning(f"Unable to remove PID file {self.pidfile_path}: {e}")

    def daemonize(self):
        if not self.args.foreground:
            self.logger.info("Daemonizing process...")
            try:
                pid = os.fork()
                if pid > 0:
                    # Exit first parent
                    sys.exit(0)
            except OSError as e:
                self.logger.error(f"fork #1 failed: {e.errno} ({e.strerror})")
                sys.exit(1)

            os.chdir("/")
            os.setsid()
            os.umask(0)

            try:
                pid = os.fork()
                if pid > 0:
                    # Exit second parent
                    sys.exit(0)
            except OSError as e:
                self.logger.error(f"fork #2 failed: {e.errno} ({e.strerror})")
                sys.exit(1)

            self.logger.info("Successfully daemonized.")

            # Redirect standard file descriptors
            sys.stdout.flush()
            sys.stderr.flush()
            si = open(os.devnull, 'r')
            so = open(os.devnull, 'a+') # Could redirect to log file if needed
            se = open(os.devnull, 'a+')
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno()) # All prints will go to devnull unless logging is to file/syslog
            os.dup2(se.fileno(), sys.stderr.fileno()) # All errors too. Logging should be robust.
        else:
            self.logger.info("Running in foreground.")

    def signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}. Shutting down...")
        self.running = False
        # Further cleanup can be added here if sockets are open etc.

    def setup_sockets_v4(self):
        self.logger.info(f"Setting up DHCPv4 sockets...")
        try:
            # Socket to listen for client broadcasts on client_iface
            self.sock_v4_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_v4_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_v4_client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Binding to specific interface for listening requires tricks or using PF_PACKET.
            # For SOCK_DGRAM, binding to '0.0.0.0' or a specific IP on the interface.
            # If client_iface has multiple IPs, this needs care.
            # For now, let's assume client_iface is the name and we bind to 0.0.0.0 on client port.
            # The OS should route packets for this interface to this socket.
            # A better way for specific interface listening with SOCK_DGRAM is to bind to one of the IPs on that interface.
            # For now, a simple bind. This might need SO_BINDTODEVICE which is Linux specific and needs root.
            self.sock_v4_client.bind(('', DHCP_CLIENT_PORT)) # Listen on all interfaces for client port
            self.logger.info(f"DHCPv4 client listening socket bound to port {DHCP_CLIENT_PORT}")

            # Socket to send to/receive from DHCP server (will bind to server_iface IP later if needed for source IP control)
            self.sock_v4_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_v4_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Might need to bind this to an IP on server_iface if server expects specific source IP
            # self.sock_v4_server.bind((self.args.server_iface_ip, 0)) # Example
            self.logger.info(f"DHCPv4 server communication socket created.")

        except OSError as e:
            self.logger.error(f"Error setting up DHCPv4 sockets: {e}")
            sys.exit(1)

    # TODO: setup_sockets_v6
        # Add a dictionary to store transaction states if needed for matching replies to requests
        self.pending_transactions = {} # xid -> client_addr_info (e.g., MAC, original source port)

    def parse_dhcpv4_options(self, options_data):
        """Parses DHCP options (TLV format)."""
        options = {}
        i = 0
        while i < len(options_data):
            option_code = options_data[i]
            i += 1
            if option_code == 0:  # Pad option
                continue
            if option_code == 255:  # End option
                break
            if i >= len(options_data): # Avoid index error if length byte is missing
                self.logger.warning("Malformed options: missing length byte.")
                break
            option_len = options_data[i]
            i += 1
            if i + option_len > len(options_data): # Avoid index error if value is shorter than length
                self.logger.warning(f"Malformed option {option_code}: value shorter than specified length {option_len}.")
                break
            option_value = options_data[i:i + option_len]
            options[option_code] = option_value
            i += option_len
        return options

    def parse_dhcpv4_packet(self, data):
        """Parses a DHCPv4 packet and returns a dictionary of fields."""
        if len(data) < 240: # Minimum DHCP packet size (236 for header + 4 for magic cookie)
            self.logger.warning(f"Packet too short to be DHCPv4: {len(data)} bytes")
            return None

        # DHCPv4 fixed header structure:
        # op (1), htype (1), hlen (1), hops (1)
        # xid (4)
        # secs (2), flags (2)
        # ciaddr (4), yiaddr (4), siaddr (4), giaddr (4)
        # chaddr (16)
        # sname (64)
        # file (128)
        # magic cookie (4) - 0x63825363
        # options (variable)

        header_format = '!BBBB I HH IIII 16s 64s 128s' # Total 236 bytes
        # Magic cookie is 4 bytes: 0x63, 0x82, 0x53, 0x63
        # Options follow

        try:
            op, htype, hlen, hops, \
            xid, \
            secs, flags, \
            ciaddr_raw, yiaddr_raw, siaddr_raw, giaddr_raw, \
            chaddr, sname, file_ = struct.unpack(header_format, data[:236])

            magic_cookie_offset = 236
            magic_cookie = data[magic_cookie_offset:magic_cookie_offset+4]
            if magic_cookie != b'\x63\x82\x53\x63':
                self.logger.warning("Invalid DHCP magic cookie.")
                return None

            options_data = data[magic_cookie_offset+4:]
            parsed_options = self.parse_dhcpv4_options(options_data)

            packet_info = {
                'op': op, 'htype': htype, 'hlen': hlen, 'hops': hops,
                'xid': xid,
                'secs': secs, 'flags': flags,
                'ciaddr': socket.inet_ntoa(ciaddr_raw),
                'yiaddr': socket.inet_ntoa(yiaddr_raw),
                'siaddr': socket.inet_ntoa(siaddr_raw),
                'giaddr': socket.inet_ntoa(giaddr_raw),
                'chaddr': chaddr[:hlen], # Only take hlen bytes for MAC
                'sname': sname.split(b'\x00', 1)[0], # Null-terminated
                'file': file_.split(b'\x00', 1)[0], # Null-terminated
                'options': parsed_options
            }
            return packet_info
        except struct.error as e:
            self.logger.error(f"Error unpacking DHCPv4 packet: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error parsing DHCPv4 packet: {e}")
            return None


    def handle_dhcpv4_packet(self, data, addr):
        self.logger.info(f"Received DHCPv4 packet from {addr}, {len(data)} bytes.")

        parsed_packet = self.parse_dhcpv4_packet(data)
        if not parsed_packet:
            self.logger.warning("Failed to parse DHCPv4 packet. Dropping.")
            return

        self.logger.debug(f"Parsed DHCPv4 packet: {parsed_packet}")

        dhcp_message_type_opt = parsed_packet['options'].get(53) # Option 53: DHCP Message Type
        if dhcp_message_type_opt:
            # Ensure the option value is not empty before trying to unpack
            if len(dhcp_message_type_opt) == 1:
                dhcp_message_type = struct.unpack('!B', dhcp_message_type_opt)[0]
                self.logger.info(f"DHCP Message Type: {dhcp_message_type}")
            else:
                self.logger.warning(f"Malformed DHCP Message Type (Option 53): length is {len(dhcp_message_type_opt)}, expected 1.")
                return
        else:
            self.logger.warning("DHCP Message Type (Option 53) not found in packet.")
            return


        # For Iteration 1, we primarily care about DISCOVER to relay to server
        if parsed_packet['op'] == BOOTREQUEST and dhcp_message_type == DHCPDISCOVER:
            self.logger.info(f"Processing DHCPDISCOVER from chaddr: {parsed_packet['chaddr'].hex()}")

            modified_data = self.modify_discover_for_server(data, self.args.giaddr, parsed_packet['hops'])
            if not modified_data:
                self.logger.error("Failed to modify DHCPDISCOVER packet.")
                return

            if self.args.target_dhcpv4_server:
                self.logger.info(f"Relaying modified DHCPDISCOVER to server {self.args.target_dhcpv4_server}:{DHCP_SERVER_PORT} (giaddr: {self.args.giaddr})")
                try:
                    self.sock_v4_server.sendto(modified_data, (self.args.target_dhcpv4_server, DHCP_SERVER_PORT))
                except Exception as e:
                    self.logger.error(f"Error sending to DHCPv4 server: {e}")
            else:
                self.logger.warning("No target DHCPv4 server configured to relay to.")
        else:
            self.logger.info(f"Ignoring non-DISCOVER DHCPv4 packet (type: {dhcp_message_type}, op: {parsed_packet['op']}).")


    def run(self):
        if not self.args.foreground:
            self.daemonize()

        self.write_pidfile()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.setup_sockets_v4()
        # TODO: self.setup_sockets_v6()

        self.logger.info("Python DHCP Relay Agent started.")
        self.logger.info(f"Client-facing interface: {self.args.client_iface} (intended)")
        self.logger.info(f"Server-facing interface: {self.args.server_iface} (intended)")
        # Log other relevant args

        # Main loop - very simplified, only listens on v4 client socket for now
        # A real implementation would use select() or asyncio for multiple sockets (v4, v6, server replies)

        if not self.sock_v4_client:
            self.logger.error("DHCPv4 client socket not initialized. Exiting.")
            return

        while self.running:
            try:
                # For now, only handle v4 client requests
                self.logger.debug("Waiting for DHCPv4 packet from client...")
                data, addr = self.sock_v4_client.recvfrom(1024) # Buffer size
                self.handle_dhcpv4_packet(data, addr)

                # TODO: Add handling for self.sock_v4_server replies
                # TODO: Add select() loop to handle multiple sockets (v4 client, v4 server, v6 client, v6 server)

            except socket.timeout:
                continue # Allow checking self.running
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}")
                # Potentially add a small sleep to prevent rapid looping on persistent errors
                time.sleep(0.1)

        self.logger.info("Shutting down relay agent...")
        if self.sock_v4_client: self.sock_v4_client.close()
        if self.sock_v4_server: self.sock_v4_server.close()
        # TODO: Close IPv6 sockets
        self.remove_pidfile()
        self.logger.info("Python DHCP Relay Agent stopped.")


def main():
    parser = argparse.ArgumentParser(description="Python DHCP Relay Agent")
    parser.add_argument('--client-iface', required=True, help="Client-facing network interface name (e.g., v_pyrelay_c_ns).")
    parser.add_argument('--server-iface', required=True, help="Server-facing network interface name (e.g., v_pyrelay_s_ns).")

    # For Iteration 1, focusing on DHCPv4 and a single target server & giaddr
    parser.add_argument('--target-dhcpv4-server', required=True, help="IP address of the target Kea DHCPv4 server.")
    parser.add_argument('--giaddr', required=True, help="Gateway IP Address (giaddr) to set in relayed DHCPv4 packets.")
    # DHCPv6 arguments will be added in later iterations
    # parser.add_argument('--target-dhcpv6-server', help="IP address of the target Kea DHCPv6 server.")
    # parser.add_argument('--link-address-v6', help="IPv6 Link Address to use in Relay-Forward messages.")

    parser.add_argument('--pid-file', required=True, help="Path to PID file.")
    parser.add_argument('--log-file', help="Path to log file. If not specified, logs to stdout/stderr based on foreground mode.")
    parser.add_argument('--log-level', default='info', choices=LOG_LEVELS.keys(), help="Logging level.")
    parser.add_argument('-f', '--foreground', action='store_true', help="Run in foreground (do not daemonize).")

    args = parser.parse_args()

    relay_agent = DHCPRelayAgent(args)

    try:
        relay_agent.run()
    except KeyboardInterrupt:
        print("Ctrl+C received, shutting down relay agent...")
        relay_agent.running = False
        # If run() is already in its cleanup phase due to signal_handler, this is fine.
        # If run() was blocked on recvfrom, signal_handler should have set self.running to False.
    except Exception as e:
        if relay_agent.logger:
            relay_agent.logger.critical(f"Unhandled exception: {e}", exc_info=True)
        else:
            sys.stderr.write(f"Critical unhandled exception before logger init: {e}\n")
    finally:
        # Ensure pidfile is removed if an unhandled exception occurred before normal shutdown
        if relay_agent and os.path.exists(relay_agent.pidfile_path) and str(os.getpid()) == open(relay_agent.pidfile_path).read().strip():
             relay_agent.remove_pidfile()


if __name__ == '__main__':
    main()
