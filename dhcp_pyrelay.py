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

    def handle_dhcpv4_packet(self, data, addr):
        self.logger.info(f"Received DHCPv4 packet from {addr}, {len(data)} bytes.")
        # TODO: Parse packet (struct, scapy)
        # TODO: Implement logic: set giaddr, determine target server
        # TODO: Forward to server self.args.red_server_v4 (hardcoded for Iteration 1)
        # TODO: Receive reply from server
        # TODO: Forward reply to client

        # Example: hardcoded forward to RED server's primary subnet
        # This is highly simplified. Real parsing and giaddr setting needed.
        if self.args.red_server_v4:
            # For now, just echo back for testing socket.
            # In reality, modify 'data' here, especially giaddr.
            # For Iteration 1, giaddr would be e.g. 192.168.10.254
            # The packet options (chaddr, xid etc) also need to be correct.
            # This is where packet crafting / modification happens.

            # Placeholder: set giaddr (offset 24, 4 bytes)
            # This requires packet to be mutable and knowing its structure.
            # For now, assume data is just relayed as is for testing connectivity.
            # A real relay MUST set giaddr if it's 0.

            # op = data[0]
            # if op == BOOTREQUEST:
            #    mutable_packet = bytearray(data)
            #    # Example: if giaddr is 0 (offset 24 for 4 bytes)
            #    # struct.pack_into('!I', mutable_packet, 24, socket.inet_aton('192.168.10.254'))
            #    # data = bytes(mutable_packet)

            self.logger.info(f"Relaying to DHCPv4 server {self.args.red_server_v4}:{DHCP_SERVER_PORT}")
            try:
                self.sock_v4_server.sendto(data, (self.args.red_server_v4, DHCP_SERVER_PORT))
            except Exception as e:
                self.logger.error(f"Error sending to DHCPv4 server: {e}")
        else:
            self.logger.warning("No DHCPv4 server configured for RED VRF to relay to.")


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

    # For Iteration 1, we might hardcode target servers or simplify.
    # These are the IPs of the Kea servers in their respective namespaces.
    parser.add_argument('--red-server-v4', help="IP address of the RED Kea DHCPv4 server.")
    parser.add_argument('--red-server-v6', help="IP address of the RED Kea DHCPv6 server.")
    parser.add_argument('--blue-server-v4', help="IP address of the BLUE Kea DHCPv4 server.")
    parser.add_argument('--blue-server-v6', help="IP address of the BLUE Kea DHCPv6 server.")

    parser.add_argument('--pid-file', required=True, help="Path to PID file.")
    parser.add_argument('--log-file', help="Path to log file. If not specified, logs to stdout.")
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
