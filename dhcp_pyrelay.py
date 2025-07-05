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

# DHCPv6 Message Types
DHCPV6_MSG_TYPE_OFFSET = 0
DHCPV6_TRANSACTION_ID_OFFSET = 1 # Relative to msg-type for client messages

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
    DHCPV6_OPTION_RELAY_MSG = 9       # Relay Message option
    DHCPV6_OPTION_STATUS_CODE = 13
    DHCPV6_OPTION_USER_CLASS = 15
    DHCPV6_OPTION_VENDOR_CLASS = 16
    DHCPV6_OPTION_INTERFACE_ID = 18   # Interface-ID option used by relays
    DHCPV6_OPTION_IA_PD = 25
    DHCPV6_OPTION_IAPREFIX = 26

    # Option 82 Sub-option codes (DHCPv4)
    AGENT_CIRCUIT_ID_SUBOPTION = 1
    AGENT_REMOTE_ID_SUBOPTION = 2

    def _parse_dhcpv6_options_generic(self, options_bytes):
        options = {}
        i = 0
        while i < len(options_bytes):
            if i + 4 > len(options_bytes):
                self.logger.warning(f"DHCPv6 options truncated: not enough data for option header at offset {i}")
                break
            opt_code = struct.unpack('!H', options_bytes[i:i+2])[0]
            opt_len = struct.unpack('!H', options_bytes[i+2:i+4])[0]
            i += 4
            if i + opt_len > len(options_bytes):
                self.logger.warning(f"DHCPv6 Option {opt_code}: value shorter than specified length {opt_len}.")
                break
            opt_value = options_bytes[i:i+opt_len]
            if opt_code not in options: options[opt_code] = []
            options[opt_code].append(opt_value)
            i += opt_len
        return options

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
        except IOError as e: self.logger.error(f"Unable to write PID file {self.pidfile_path}: {e}"); sys.exit(1)

    def remove_pidfile(self):
        try:
            if os.path.exists(self.pidfile_path): os.remove(self.pidfile_path); self.logger.info(f"PID file {self.pidfile_path} removed.")
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
            si=open(os.devnull,'r'); so=open(os.devnull,'a+'); se=open(os.devnull,'a+')
            os.dup2(si.fileno(),sys.stdin.fileno()); os.dup2(so.fileno(),sys.stdout.fileno()); os.dup2(se.fileno(),sys.stderr.fileno())
        else: self.logger.info("Running in foreground.")

    def signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}. Shutting down...")
        self.running = False

    def setup_sockets_v4(self):
        self.logger.info("Setting up DHCPv4 sockets...")
        try:
            self.sock_v4_client=socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP); self.sock_v4_client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); self.sock_v4_client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); self.sock_v4_client.bind(('',DHCP_CLIENT_PORT)); self.logger.info(f"DHCPv4 client listening socket bound to port {DHCP_CLIENT_PORT}")
            self.sock_v4_server=socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP); self.sock_v4_server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); self.logger.info("DHCPv4 server communication socket created.")
            return True
        except OSError as e: self.logger.error(f"Error setting up DHCPv4 sockets: {e}"); self.sock_v4_client=None; return False

    def setup_sockets_v6(self):
        is_any_v6_server_configured = self.args.red_server_v6 or self.args.blue_server_v6
        if not is_any_v6_server_configured:
            self.logger.info("No DHCPv6 servers (RED or BLUE) configured. Skipping DHCPv6 socket setup.")
            return False

        self.logger.info("Setting up DHCPv6 sockets...")
        try:
            self.sock_v6_client=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP); self.sock_v6_client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            idx=0;
            if self.args.client_iface:
                try: idx=socket.if_nametoindex(self.args.client_iface)
                except OSError as e: self.logger.error(f"Cannot get index for iface {self.args.client_iface}: {e}. MCast join may fail.");
            self.sock_v6_client.bind(('', DHCPV6_SERVER_PORT)); self.logger.info(f"DHCPv6 client listening bound to [::]:{DHCPV6_SERVER_PORT}")
            if idx!=0: mreq=socket.inet_pton(socket.AF_INET6, "ff02::1:2")+struct.pack("I",idx); self.sock_v6_client.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_JOIN_GROUP,mreq); self.logger.info(f"Joined ff02::1:2 on {self.args.client_iface} (idx {idx})")
            else: self.logger.warning(f"Could not get iface index for {self.args.client_iface}. MCast group NOT joined.")
            self.sock_v6_server=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP); self.sock_v6_server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); self.logger.info("DHCPv6 server comms socket created.")
            return True
        except OSError as e:
            self.logger.error(f"Error setting up DHCPv6 sockets: {e}")
            if self.sock_v6_client: self.sock_v6_client.close(); self.sock_v6_client = None
            if self.sock_v6_server: self.sock_v6_server.close(); self.sock_v6_server = None
            return False

    def parse_dhcpv4_options(self, options_data):
        opts={}; i=0
        while i<len(options_data):
            oc=options_data[i]; i+=1
            if oc==self.DHCP_OPTION_PAD: continue
            if oc==self.DHCP_OPTION_END: break
            if i>=len(options_data): self.logger.warning("MalformedV4Opts:no len"); break
            ol=options_data[i]; i+=1
            if i+ol > len(options_data): self.logger.warning(f"V4Opt {oc}:val<len {ol}"); break
            opts[oc]=options_data[i:i+ol]; i+=ol
        return opts

    def parse_dhcpv4_packet(self, data):
        if len(data)<240: self.logger.warning(f"Pkt too shortV4:{len(data)}B"); return None
        fmt='!BBBB I HH IIII 16s 64s 128s'
        try:
            op,ht,hl,hops,xid,secs,flgs,ci_raw,yi_raw,si_raw,gi_raw,ch,sn,fn = struct.unpack(fmt,data[:236])
            if data[236:240]!=b'\x63\x82\x53\x63': self.logger.warning("BadV4Magic"); return None
            options=self.parse_dhcpv4_options(data[240:])
            return {'op':op,'htype':ht,'hlen':hl,'hops':hops,'xid':xid,'secs':secs,'flags':flgs,
                    'ciaddr':socket.inet_ntoa(ci_raw),'yiaddr':socket.inet_ntoa(yi_raw),
                    'siaddr':socket.inet_ntoa(si_raw),'giaddr':socket.inet_ntoa(gi_raw),
                    'chaddr':ch[:hl],'sname':sn.split(b'\0',1)[0],'file':fn.split(b'\0',1)[0],
                    'options':options,'raw_options':data[240:]}
        except Exception as e: self.logger.error(f"Err unpack/parse V4:{e}"); return None

    def _get_mac_from_duid(self, duid_bytes):
        if not duid_bytes or len(duid_bytes) < 4: # Min DUID-LL/DUID-LLT header is 4 bytes
            return None
        duid_type = struct.unpack('!H', duid_bytes[:2])[0]
        hw_type = struct.unpack('!H', duid_bytes[2:4])[0]

        if hw_type == 1: # Ethernet
            if duid_type == 1 and len(duid_bytes) >= 14: # DUID-LLT (2 type + 2 hwtype + 4 time + 6 MAC)
                return duid_bytes[8:14]
            elif duid_type == 3 and len(duid_bytes) >= 8: # DUID-LL (2 type + 2 hwtype + 6 MAC)
                return duid_bytes[4:10]
        return None

    def parse_dhcpv6_packet(self, data_bytes, from_server=False):
        if not data_bytes or len(data_bytes)<1: self.logger.warning("Empty/short V6 pkt."); return None
        msg_type=data_bytes[0]; pkt={'msg_type':msg_type,'raw_data':data_bytes}
        if not from_server or msg_type not in [DHCPV6_RELAY_FORW, DHCPV6_RELAY_REPL]:
            if len(data_bytes)<4: self.logger.warning(f"V6 cli/simple too short (t{msg_type},l{len(data_bytes)})"); return None
            pkt['transaction_id']=data_bytes[1:4]; opts_bytes=data_bytes[4:]
            pkt['options']=self._parse_dhcpv6_options_generic(opts_bytes)
            cid_opt=pkt['options'].get(self.DHCPV6_OPTION_CLIENTID)
            pkt['client_duid']=cid_opt[0] if cid_opt and len(cid_opt)>0 else None
            if not from_server and not pkt['client_duid']: self.logger.debug(f"No DUID in cli msg {msg_type}")
        elif msg_type==DHCPV6_RELAY_REPL:
            if len(data_bytes)<34: self.logger.warning(f"V6 RelayRepl too short (l{len(data_bytes)})"); return None
            try:
                pkt['hop_count']=data_bytes[1]
                pkt['link_address']=socket.inet_ntop(socket.AF_INET6,data_bytes[2:18])
                pkt['peer_address']=socket.inet_ntop(socket.AF_INET6,data_bytes[18:34])
                opts_bytes=data_bytes[34:]; pkt['options']=self._parse_dhcpv6_options_generic(opts_bytes)
                relay_msg_opt=pkt['options'].get(self.DHCPV6_OPTION_RELAY_MSG)
                pkt['encapsulated_message']=relay_msg_opt[0] if relay_msg_opt and len(relay_msg_opt)>0 else None
                if not pkt['encapsulated_message']: self.logger.warning("RelayRepl missing Opt9")
            except Exception as e: self.logger.error(f"Err proc V6 RelayRepl:{e}"); return None
        else: self.logger.warning(f"Unexpected V6 msg_type {msg_type} from_server={from_server}"); return None
        return pkt

    def _craft_dhcpv6_option(self, option_code, option_value_bytes):
        return struct.pack('!HH', option_code, len(option_value_bytes)) + option_value_bytes
    def _craft_relay_msg_option(self, client_msg_bytes):
        return self._craft_dhcpv6_option(self.DHCPV6_OPTION_RELAY_MSG, client_msg_bytes)
    def _craft_interface_id_option(self, interface_id_str):
        if not interface_id_str: return b''
        return self._craft_dhcpv6_option(self.DHCPV6_OPTION_INTERFACE_ID, interface_id_str.encode('ascii'))

    def craft_relay_forward_message(self, client_msg_bytes, hop_count, link_address_ipv6_str, peer_address_ipv6_str, relay_options_bytes=None):
        try:
            link_addr_bytes=socket.inet_pton(socket.AF_INET6,link_address_ipv6_str)
            peer_addr_bytes=socket.inet_pton(socket.AF_INET6,peer_address_ipv6_str)
        except socket.error as e: self.logger.error(f"Invalid IPv6 for RelayFwd link/peer: {e}"); return None
        hdr=bytearray([DHCPV6_RELAY_FORW, hop_count%256]); hdr.extend(link_addr_bytes); hdr.extend(peer_addr_bytes)
        opts=bytearray(self._craft_relay_msg_option(client_msg_bytes))
        if relay_options_bytes: opts.extend(relay_options_bytes)
        self.logger.debug(f"Crafted RelayFwd: hdr_len {len(hdr)}, opts_len {len(opts)}")
        return bytes(hdr)+bytes(opts)

    def add_option82(self, opts_data, circuit_id, remote_id=None):
        opts=bytearray(opts_data); payload=bytearray()
        if circuit_id: cid_b=circuit_id.encode('ascii'); payload.extend([self.AGENT_CIRCUIT_ID_SUBOPTION,len(cid_b)]); payload.extend(cid_b)
        if remote_id:  rid_b=remote_id.encode('ascii');  payload.extend([self.AGENT_REMOTE_ID_SUBOPTION,len(rid_b)]);  payload.extend(rid_b)
        if not payload: return bytes(opts_data)

        end_idx = -1
        try: end_idx = opts.rindex(self.DHCP_OPTION_END)
        except ValueError: pass

        insert_pos = end_idx
        if end_idx != -1:
            temp_pos = end_idx -1
            while temp_pos >= 0 and opts[temp_pos] == self.DHCP_OPTION_PAD:
                insert_pos = temp_pos
                temp_pos -=1
        else:
            insert_pos = len(opts)

        final_opts = opts[:insert_pos]
        final_opts.extend([self.DHCP_OPTION_RELAY_AGENT_INFO, len(payload)])
        final_opts.extend(payload)
        final_opts.append(self.DHCP_OPTION_END)
        self.logger.debug(f"Added Opt82. New opts len: {len(final_opts)}")
        return bytes(final_opts)

    def strip_option82(self, options_data):
        new_opts=bytearray(); i=0; orig_opts=bytes(options_data)
        while i<len(orig_opts):
            code=orig_opts[i]
            if code==self.DHCP_OPTION_END: new_opts.append(code); break
            if code==self.DHCP_OPTION_PAD: new_opts.append(code); i+=1; continue
            if i+1>=len(orig_opts): break
            length=orig_opts[i+1]
            if i + 2 + length > len(orig_opts): self.logger.warning(f"Opt {code}: value shorter than actual len {length}."); break

            if code!=self.DHCP_OPTION_RELAY_AGENT_INFO: new_opts.extend(orig_opts[i:i+2+length])
            else: self.logger.info("Stripped Opt82")
            i+=(2+length)
        if not new_opts or new_opts[-1]!=self.DHCP_OPTION_END: new_opts.append(self.DHCP_OPTION_END)
        return bytes(new_opts)

    def _modify_client_packet_for_server(self, pkt_data, giaddr_str, hops): # Renamed
        if len(pkt_data)<236: self.logger.error("Pkt too short to mod"); return None
        mod_pkt=bytearray(pkt_data)
        try:
            struct.pack_into('!4s',mod_pkt,24,socket.inet_aton(giaddr_str))
            mod_pkt[3]=(hops+1)%256
            self.logger.debug(f"giaddr={giaddr_str}, hops={mod_pkt[3]}")
            return bytes(mod_pkt)
        except Exception as e: self.logger.error(f"Err mod V4 for srv: {e}"); return None

    def handle_dhcpv4_from_client(self, data, client_addr):
        self.logger.info(f"Rcvd V4 from cli {client_addr}, {len(data)}B")
        parsed=self.parse_dhcpv4_packet(data)
        if not parsed: self.logger.warning("Fail parse V4 from cli"); return
        self.logger.debug(f"Parsed cli V4: {parsed}")
        msg_type_opt=parsed['options'].get(self.DHCP_OPTION_MESSAGE_TYPE)
        if not msg_type_opt or len(msg_type_opt)!=1: self.logger.warning("V4 MsgType opt err"); return
        msg_type=msg_type_opt[0]
        self.logger.info(f"Cli V4 MsgType: {msg_type}")

        if parsed['op']==BOOTREQUEST and msg_type in [DHCPDISCOVER, DHCPREQUEST]:
            mac_str = parsed['chaddr'].hex(':')
            self.logger.info(f"Proc V4 {('DISC' if msg_type==DHCPDISCOVER else 'REQ')} from MAC: {mac_str}")

            target_server_ip = None
            giaddr_to_use = None
            target_vrf = None

            if mac_str.startswith("00:aa"):
                target_vrf = "RED"
                target_server_ip = self.args.red_server_v4
                giaddr_to_use = self.args.red_giaddr
            elif mac_str.startswith("00:bb"):
                target_vrf = "BLUE"
                target_server_ip = self.args.blue_server_v4
                giaddr_to_use = self.args.blue_giaddr
            else:
                self.logger.warning(f"MAC {mac_str} not mapped to any VRF. Dropping V4 packet.")
                return

            if not target_server_ip or not giaddr_to_use:
                self.logger.warning(f"Target server IP or giaddr not configured for VRF {target_vrf}. Dropping V4 packet.")
                return

            self.pending_transactions_v4[parsed['xid']]={'chaddr':parsed['chaddr'],'client_addr':client_addr,'ts':time.time(), 'vrf': target_vrf}
            self.logger.debug(f"Stored v4 transaction {parsed['xid']} for chaddr {mac_str} -> VRF {target_vrf}")

            circuit_id_to_add=None
            if target_vrf == "RED":
                if mac_str.startswith("00:aa:01"): circuit_id_to_add="VIDEO_CIRCUIT"
                elif mac_str.startswith("00:aa:02"): circuit_id_to_add="DATA_CIRCUIT"
            elif target_vrf == "BLUE":
                if mac_str.startswith("00:bb:01"): circuit_id_to_add="VIDEO_CIRCUIT"
                elif mac_str.startswith("00:bb:02"): circuit_id_to_add="DATA_CIRCUIT"

            hdr_magic=data[:240]; opts_part=parsed['raw_options']
            if circuit_id_to_add: self.logger.info(f"Policy: Add Opt82 CID={circuit_id_to_add} for VRF {target_vrf}"); opts_part=self.add_option82(opts_part,circuit_id_to_add)

            pkt_opt82=hdr_magic+opts_part
            mod_data=self._modify_client_packet_for_server(pkt_opt82, giaddr_to_use, parsed['hops'])

            if not mod_data: self.logger.error("Fail mod V4 for srv");self._del_pending_v4(parsed['xid']); return

            self.logger.info(f"Relay V4 to srv {target_server_ip} (giaddr:{giaddr_to_use}) for VRF {target_vrf}")
            try: self.sock_v4_server.sendto(mod_data,(target_server_ip,DHCP_SERVER_PORT))
            except Exception as e: self.logger.error(f"Err send V4 to srv:{e}"); self._del_pending_v4(parsed['xid'])
        else: self.logger.info(f"Ignore V4 (type:{msg_type},op:{parsed['op']})")

    def _del_pending_v4(self, xid):
        if xid in self.pending_transactions_v4: del self.pending_transactions_v4[xid]

    def handle_dhcpv4_from_server(self, data, server_addr):
        self.logger.info(f"Rcvd V4 from srv {server_addr}, {len(data)}B")
        parsed=self.parse_dhcpv4_packet(data)
        if not parsed: self.logger.warning("Fail parse V4 from srv"); return
        self.logger.debug(f"Parsed srv V4: {parsed}")
        msg_type_opt=parsed['options'].get(self.DHCP_OPTION_MESSAGE_TYPE)
        if not msg_type_opt or len(msg_type_opt)!=1: self.logger.warning("Srv V4 MsgType opt err"); return
        msg_type=msg_type_opt[0]; self.logger.info(f"Srv V4 MsgType: {msg_type}")

        trans_info=self.pending_transactions_v4.get(parsed['xid'])
        if not trans_info: self.logger.warning(f"Rcvd V4 for unknown xid {parsed['xid']}"); return

        if parsed['op']==BOOTREPLY and msg_type in [DHCPOFFER, DHCPACK]:
            self.logger.info(f"Proc V4 {('OFFER' if msg_type==DHCPOFFER else 'ACK')} for xid:{parsed['xid']},yiaddr:{parsed['yiaddr']}")
            hdr_magic=data[:240]; opts_part=parsed['raw_options']
            stripped_opts=self.strip_option82(opts_part); pkt_for_cli=hdr_magic+stripped_opts
            dest_cli_seg=('255.255.255.255',DHCP_CLIENT_PORT)
            self.logger.info(f"Relay V4 to cli seg for MAC {trans_info['chaddr'].hex()}")
            try: self.sock_v4_client.sendto(pkt_for_cli,dest_cli_seg)
            except Exception as e: self.logger.error(f"Err relay V4 to cli:{e}")
            if msg_type==DHCPACK: self._del_pending_v4(parsed['xid']); self.logger.debug(f"V4 Trans {parsed['xid']} done.")
        else: self.logger.info(f"Ignore other V4 from srv (type:{msg_type},op:{parsed['op']})")

    def handle_dhcpv6_from_client(self, data, client_addr_info):
        self.logger.info(f"Rcvd DHCPv6 from {client_addr_info[0]}%{client_addr_info[3]} p:{client_addr_info[1]}, {len(data)}B")
        parsed_msg = self.parse_dhcpv6_packet(data, from_server=False)
        if not parsed_msg: self.logger.warning("Fail parse V6 cli msg"); return
        self.logger.debug(f"Parsed V6 cli: {parsed_msg}")

        msg_type = parsed_msg['msg_type']
        tid = parsed_msg.get('transaction_id')

        if msg_type in [DHCPV6_SOLICIT, DHCPV6_REQUEST, DHCPV6_RENEW, DHCPV6_REBIND, DHCPV6_CONFIRM, DHCPV6_INFORMATION_REQUEST, DHCPV6_RELEASE, DHCPV6_DECLINE] and tid:
            client_duid_bytes = parsed_msg.get('client_duid')
            self.logger.info(f"Proc V6 MsgType {msg_type} from DUID:{client_duid_bytes.hex() if client_duid_bytes else 'N/A'} TID:{tid.hex()}")

            target_server_ip_v6 = None
            link_address_to_use = None
            target_vrf = None
            client_mac_bytes = self._get_mac_from_duid(client_duid_bytes)

            if client_mac_bytes:
                mac_str = client_mac_bytes.hex(':')
                if mac_str.startswith("00:aa"):
                    target_vrf = "RED"
                    target_server_ip_v6 = self.args.red_server_v6
                    link_address_to_use = self.args.red_link_address_v6
                elif mac_str.startswith("00:bb"):
                    target_vrf = "BLUE"
                    target_server_ip_v6 = self.args.blue_server_v6
                    link_address_to_use = self.args.blue_link_address_v6

            if not target_vrf: # No MAC match or DUID not MAC-based
                self.logger.warning(f"Client DUID {client_duid_bytes.hex() if client_duid_bytes else 'N/A'} not mapped to any VRF. Dropping V6 packet.")
                return

            if not target_server_ip_v6 or not link_address_to_use:
                self.logger.warning(f"Target V6 server IP or link-address not configured for VRF {target_vrf}. Dropping V6 packet.")
                return

            self.pending_transactions_v6[tid] = {'client_addr_info': client_addr_info, 'ts': time.time(), 'vrf': target_vrf}
            self.logger.debug(f"Stored v6 transaction {tid.hex()} for DUID {client_duid_bytes.hex() if client_duid_bytes else 'N/A'} -> VRF {target_vrf}")

            iface_id_str=None
            if client_mac_bytes: # Use MAC for sub-policy if available
                mac_policy_part = client_mac_bytes.hex(':')[6:8] # 00:aa:XX - get the XX part
                if mac_policy_part == "01": iface_id_str="V6_VIDEO_LINK"
                elif mac_policy_part == "02": iface_id_str="V6_DATA_LINK"
            elif client_duid_bytes: # Fallback to DUID type if MAC not usable for sub-policy
                 duid_type=struct.unpack('!H',client_duid_bytes[:2])[0]
                 if duid_type==1: iface_id_str="V6_VIDEO_LINK"
                 elif duid_type==3: iface_id_str="V6_DATA_LINK"

            relay_opts_bytes = self._craft_interface_id_option(iface_id_str) if iface_id_str else b''
            if iface_id_str: self.logger.info(f"Policy: Add V6 IfaceID={iface_id_str} for VRF {target_vrf}")

            relay_fwd_msg = self.craft_relay_forward_message(
                data, 0, link_address_to_use, client_addr_info[0], relay_opts_bytes
            )
            if not relay_fwd_msg: self.logger.error("Fail craft V6 RelayFwd"); self._del_pending_v6(tid); return

            self.logger.info(f"Relay V6 to srv {target_server_ip_v6} for VRF {target_vrf}")
            try: self.sock_v6_server.sendto(relay_fwd_msg, (target_server_ip_v6, DHCPV6_SERVER_PORT))
            except Exception as e: self.logger.error(f"Err send V6 RelayFwd:{e}"); self._del_pending_v6(tid)
        else: self.logger.info(f"Ignore V6 cli msg type {msg_type} or no TID.")

    def _del_pending_v6(self, tid_bytes):
        if tid_bytes in self.pending_transactions_v6: del self.pending_transactions_v6[tid_bytes]

    def handle_dhcpv6_from_server(self, data, server_addr_info):
        self.logger.info(f"Rcvd DHCPv6 from srv {server_addr_info}, {len(data)}B")
        parsed_msg = self.parse_dhcpv6_packet(data, from_server=True)
        if not parsed_msg: self.logger.warning("Fail parse V6 srv msg"); return
        self.logger.debug(f"Parsed V6 srv: {parsed_msg}")

        if parsed_msg['msg_type'] == DHCPV6_RELAY_REPL:
            enc_msg = parsed_msg.get('encapsulated_message')
            peer_addr_str = parsed_msg.get('peer_address')
            if not enc_msg or not peer_addr_str: self.logger.warning("RELAY_REPL missing enc_msg/peer_addr"); return

            if len(enc_msg) < 4: self.logger.warning("Encapsulated msg too short"); return
            client_tid_bytes = enc_msg[1:4]

            trans_info = self.pending_transactions_v6.get(client_tid_bytes)
            if not trans_info: self.logger.warning(f"Rcvd RELAY_REPL for unknown cli_tid {client_tid_bytes.hex()}"); return

            dest_addr_info = (peer_addr_str, DHCPV6_CLIENT_PORT, 0, trans_info['client_addr_info'][3])
            self.logger.info(f"Relay encap V6 msg to cli {dest_addr_info[0]}%{dest_addr_info[3]}:{dest_addr_info[1]}")
            try: self.sock_v6_client.sendto(enc_msg, dest_addr_info)
            except Exception as e: self.logger.error(f"Err relay V6 encap to cli: {e}")

            enc_msg_type = enc_msg[0]
            if enc_msg_type == DHCPV6_REPLY:
                self._del_pending_v6(client_tid_bytes)
                self.logger.debug(f"V6 Trans {client_tid_bytes.hex()} (REPLY) done.")
        else: self.logger.info(f"Ignoring other V6 from srv (type:{parsed_msg['msg_type']})")

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

    # Arguments for RED VRF/Namespace
    parser.add_argument('--red-server-v4', help="IP of RED Kea DHCPv4 server.")
    parser.add_argument('--red-giaddr', help="giaddr for relaying to RED DHCPv4 subnets.")
    parser.add_argument('--red-server-v6', help="IP of RED Kea DHCPv6 server.")
    parser.add_argument('--red-link-address-v6', help="Link-address for relaying to RED DHCPv6 prefixes.")

    # Arguments for BLUE VRF/Namespace
    parser.add_argument('--blue-server-v4', help="IP of BLUE Kea DHCPv4 server.")
    parser.add_argument('--blue-giaddr', help="giaddr for relaying to BLUE DHCPv4 subnets.")
    parser.add_argument('--blue-server-v6', help="IP of BLUE Kea DHCPv6 server.")
    parser.add_argument('--blue-link-address-v6', help="Link-address for relaying to BLUE DHCPv6 prefixes.")

    parser.add_argument('--pid-file', required=True, help="Path to PID file.")
    parser.add_argument('--log-file', help="Path to log file. If not specified, logs to stdout/stderr based on foreground mode.")
    parser.add_argument('--log-level', default='info', choices=LOG_LEVELS.keys(), help="Logging level.")
    parser.add_argument('-f', '--foreground', action='store_true', help="Run in foreground (do not daemonize).")

    args = parser.parse_args()

    # Basic validation for server configs if provided
    if (args.red_server_v4 and not args.red_giaddr) or \
       (args.red_server_v6 and not args.red_link_address_v6) or \
       (args.blue_server_v4 and not args.blue_giaddr) or \
       (args.blue_server_v6 and not args.blue_link_address_v6):
        parser.error("If a server IP (v4 or v6) for RED/BLUE is provided, its corresponding giaddr/link-address must also be provided.")
    if not (args.red_server_v4 or args.red_server_v6 or args.blue_server_v4 or args.blue_server_v6):
        parser.error("At least one server (RED or BLUE, v4 or v6) must be configured.")


    relay_agent = DHCPRelayAgent(args)
    try: relay_agent.run()
    except KeyboardInterrupt: print("Ctrl+C received, shutting down relay agent..."); relay_agent.running = False
    except Exception as e:
        logger_to_use = relay_agent.logger if hasattr(relay_agent, 'logger') and relay_agent.logger else logging.getLogger()
        logger_to_use.critical(f"Unhandled exception: {e}", exc_info=True)
    finally:
        if hasattr(relay_agent, 'pidfile_path') and relay_agent.pidfile_path and os.path.exists(relay_agent.pidfile_path):
             try:
                 with open(relay_agent.pidfile_path, 'r') as pf:
                     pid_in_file = pf.read().strip()
                 if pid_in_file == str(os.getpid()):
                     relay_agent.remove_pidfile()
                 else:
                    if hasattr(relay_agent, 'logger') and relay_agent.logger:
                         relay_agent.logger.warning(f"PID file {relay_agent.pidfile_path} owned by another process ({pid_in_file}). Not removing.")
                    else:
                         print(f"Warning: PID file {relay_agent.pidfile_path} owned by another process ({pid_in_file}). Not removing.", file=sys.stderr)

             except Exception as e_pid:
                 if hasattr(relay_agent, 'logger') and relay_agent.logger:
                    relay_agent.logger.error(f"Error during final PID file check/removal: {e_pid}")
                 else:
                    print(f"Error during final PID file check/removal: {e_pid}", file=sys.stderr)


if __name__ == '__main__':
    main()
