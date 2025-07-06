#!/usr/bin/env python3

import argparse
import subprocess
import os
import sys
import time
import shutil

def print_error(message):
    """Prints an error message to stderr."""
    print(f"ERROR: {message}", file=sys.stderr)

def run_command(command, check=True):
    """Runs a shell command."""
    print(f"Executing: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=check)
        # Suppress stdout/stderr from successful run_command calls unless debugging
        # if result.stdout:
        #     print(result.stdout)
        # if result.stderr:
        #     print(result.stderr, file=sys.stderr)
        return result
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {e}")
        if e.stdout: print_error(f"Stdout: {e.stdout.strip()}")
        if e.stderr: print_error(f"Stderr: {e.stderr.strip()}")
        raise
    except FileNotFoundError:
        print_error(f"Command not found: {command[0]}. Please ensure it's installed and in PATH.")
        raise

def setup_client_namespace(client_id, host_iface, veth_host_name, veth_ns_name, ns_name):
    """Sets up a network namespace for a client, creating veth pairs and connecting to host_iface."""
    print(f"Setting up namespace '{ns_name}' for client {client_id} (veth: {veth_host_name} <-> {veth_ns_name})")

    commands = [
        ['sudo', 'ip', 'netns', 'add', ns_name],
        ['sudo', 'ip', 'link', 'add', veth_host_name, 'type', 'veth', 'peer', 'name', veth_ns_name],
        ['sudo', 'ip', 'link', 'set', veth_ns_name, 'netns', ns_name],
    ]

    if host_iface:
        commands.append(['sudo', 'ip', 'link', 'set', veth_host_name, 'master', host_iface])

    commands.extend([
        ['sudo', 'ip', 'link', 'set', veth_host_name, 'up'],
        ['sudo', 'ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', 'dev', 'lo', 'up'],
        ['sudo', 'ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', 'dev', veth_ns_name, 'up']
    ])

    try:
        for cmd in commands:
            run_command(cmd)
        print(f"Namespace '{ns_name}' and interfaces for client {client_id} successfully set up.")
        return True
    except Exception as e:
        print_error(f"Failed to set up namespace for client {client_id}: {e}")
        try:
            print_error(f"Attempting partial cleanup for client {client_id} due to setup failure...")
            # Check if ns exists before trying to delete
            ns_exists_check = subprocess.run(['sudo', 'ip', 'netns', 'list'], capture_output=True, text=True)
            if ns_name in ns_exists_check.stdout:
                 run_command(['sudo', 'ip', 'netns', 'del', ns_name], check=False) # Best effort
            # Check if veth host exists before trying to delete
            if subprocess.run(['sudo', 'ip', 'link', 'show', veth_host_name], capture_output=True, text=True).returncode == 0:
                run_command(['sudo', 'ip', 'link', 'del', veth_host_name], check=False) # Best effort
        except Exception as cleanup_e:
            print_error(f"Partial cleanup for client {client_id} also failed: {cleanup_e}")
        return False

def run_perfdhcp_for_client(client_id, protocol_version, server_ip, client_iface_in_ns, rate, duration,
                            template_file, perfdhcp_path, output_dir, base_mac_or_duid_options_str, ns_name):
    """Runs perfdhcp for a client in its namespace."""
    log_file_name = f"client_{client_id}_v{protocol_version}.log"
    log_file_path = os.path.join(output_dir, log_file_name)

    print(f"Attempting to run perfdhcp for client {client_id} (IPv{protocol_version}), log: {log_file_path}...")

    cmd = ['sudo', 'ip', 'netns', 'exec', ns_name, perfdhcp_path]

    if protocol_version == 4:
        cmd.append('-4')
    elif protocol_version == 6:
        cmd.append('-6')
    else:
        print_error(f"Unsupported protocol version: {protocol_version} for perfdhcp.")
        return None

    cmd.extend(['-l', client_iface_in_ns])
    cmd.extend(['-r', str(rate)])
    cmd.extend(['-R', '1'])
    cmd.extend(['-p', str(duration)])

    if template_file:
        if os.path.isfile(template_file):
            cmd.extend(['-T', template_file])
        else:
            print_error(f"Template file {template_file} not found for client {client_id} v{protocol_version}. Ignoring template.")

    if base_mac_or_duid_options_str:
         cmd.extend(['-b', base_mac_or_duid_options_str])

    if server_ip:
         cmd.append(server_ip)
    else:
        if protocol_version == 4:
            print(f"No explicit DHCPv4 server IP for client {client_id}, perfdhcp will broadcast on {client_iface_in_ns}.")
        elif protocol_version == 6:
            print(f"No explicit DHCPv6 server IP for client {client_id}, perfdhcp will multicast to ff02::1:2 on {client_iface_in_ns}.")

    print(f"  Executing for client {client_id} (v{protocol_version}): {' '.join(cmd)}")

    try:
        log_fp = open(log_file_path, 'w')
        proc = subprocess.Popen(cmd, stdout=log_fp, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        print(f"  perfdhcp process for client {client_id} (IPv{protocol_version}) started with PID {proc.pid}.")
        return proc
    except FileNotFoundError:
        print_error(f"perfdhcp command '{perfdhcp_path}' not found. Ensure Kea tools are installed and path is correct.")
        if 'log_fp' in locals() and hasattr(log_fp, 'close'): log_fp.close()
        return None
    except Exception as e:
        print_error(f"Failed to start perfdhcp for client {client_id} (IPv{protocol_version}): {e}")
        if 'log_fp' in locals() and hasattr(log_fp, 'close'): log_fp.close()
        return None

def cleanup_client_namespace(client_id, veth_host_name, ns_name):
    """Cleans up a client's network namespace and associated veth pair."""
    print(f"Cleaning up resources for client {client_id} (namespace: {ns_name}, veth host: {veth_host_name})...")

    ns_deleted_successfully = False
    veth_deleted_successfully = False

    # Attempt to delete namespace
    ns_exists_check = subprocess.run(['sudo', 'ip', 'netns', 'list'], capture_output=True, text=True)
    if ns_name in ns_exists_check.stdout:
        print(f"Attempting to delete namespace: {ns_name}")
        try:
            run_command(['sudo', 'ip', 'netns', 'del', ns_name], check=True)
            print(f"Namespace {ns_name} deleted.")
            ns_deleted_successfully = True
        except subprocess.CalledProcessError as e:
            print_error(f"Command to delete namespace {ns_name} failed: {e}. It might be busy or already partially removed.")
        except FileNotFoundError:
             print_error(f"'ip' command not found during namespace {ns_name} cleanup.")
             print(f"Cleanup for client {client_id} likely incomplete due to missing 'ip' command.")
             return # Cannot proceed with veth cleanup if 'ip' is missing
    else:
        print(f"Namespace {ns_name} not found or already deleted.")
        ns_deleted_successfully = True

    # Attempt to delete host-side veth interface
    try:
        link_show_cmd = ['sudo', 'ip', 'link', 'show', veth_host_name]
        veth_exists_check = subprocess.run(link_show_cmd, capture_output=True, text=True)

        if veth_exists_check.returncode == 0:
            print(f"Attempting to delete host veth interface: {veth_host_name}")
            run_command(['sudo', 'ip', 'link', 'del', veth_host_name], check=True)
            print(f"Host veth interface {veth_host_name} deleted.")
            veth_deleted_successfully = True
        else:
            print(f"Host veth interface {veth_host_name} not found or already deleted.")
            veth_deleted_successfully = True # Consider it cleaned if not found
    except subprocess.CalledProcessError as e:
        print_error(f"Command to delete veth {veth_host_name} failed: {e}")
    except FileNotFoundError:
        print_error(f"'ip' command not found during veth {veth_host_name} cleanup.")
    except Exception as e:
        print_error(f"Unexpected error during veth {veth_host_name} cleanup: {e}")

    if ns_deleted_successfully and veth_deleted_successfully:
        print(f"Cleanup for client {client_id} completed successfully.")
    else:
        print_error(f"Cleanup for client {client_id} partially completed. Please check logs for errors.")

def main():
    parser = argparse.ArgumentParser(description="Dual Stack DHCP Client Simulator using Kea perfdhcp.")
    parser.add_argument("--num-clients", type=int, required=True, help="Number of dual-stack clients to simulate.")
    parser.add_argument("--host-iface", type=str, required=True, help="Host-side network interface or bridge (e.g., br0).")
    parser.add_argument("--dhcpv4-server", type=str, help="IP/Broadcast address for DHCPv4 server/relay. Skips v4 if not provided.")
    parser.add_argument("--dhcpv6-server", type=str, help="IP/Multicast address for DHCPv6 server/relay. Skips v6 if not provided.")
    parser.add_argument("--rate", type=int, default=10, help="Target requests per second per client per protocol.")
    parser.add_argument("--duration", type=int, default=60, help="Duration of the test in seconds for each client.")
    parser.add_argument("--v4-template", type=str, help="Path to a custom DHCPv4 packet template for perfdhcp.")
    parser.add_argument("--v6-template", type=str, help="Path to a custom DHCPv6 packet template for perfdhcp.")
    parser.add_argument("--perfdhcp-path", type=str, default="/usr/sbin/perfdhcp", help="Path to perfdhcp executable.")
    parser.add_argument("--output-dir", type=str, default="perfdhcp_results", help="Directory to store perfdhcp output logs.")
    parser.add_argument("--base-mac", type=str, help="Base MAC for clients (e.g., 00:00:00:00:00:00). Last octet increments.")
    parser.add_argument("--base-duid", type=str, help="Base DUID (hex) for clients. Last byte increments.")

    args = parser.parse_args()

    if not args.dhcpv4_server and not args.dhcpv6_server:
        print_error("At least one of --dhcpv4-server or --dhcpv6-server must be specified.")
        sys.exit(1)

    if os.geteuid() != 0:
        print_error("This script requires root privileges for network namespace and interface manipulation.")
        sys.exit(1)

    if os.path.exists(args.output_dir):
        print(f"Output directory {args.output_dir} exists. Removing and recreating.")
        try:
            shutil.rmtree(args.output_dir)
        except OSError as e:
            print_error(f"Error removing directory {args.output_dir}: {e}")
            sys.exit(1)
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as e:
        print_error(f"Error creating directory {args.output_dir}: {e}")
        sys.exit(1)

    print(f"Storing results in {args.output_dir}")
    print(f"Starting simulation with {args.num_clients} client(s).")
    print(f"Host interface: {args.host_iface}")
    if args.dhcpv4_server: print(f"DHCPv4 Target: {args.dhcpv4_server}")
    if args.dhcpv6_server: print(f"DHCPv6 Target: {args.dhcpv6_server}")
    print(f"Rate: {args.rate} rps, Duration: {args.duration}s")
    print(f"Perfdhcp path: {args.perfdhcp_path}")

    if not os.path.isfile(args.perfdhcp_path) or not os.access(args.perfdhcp_path, os.X_OK):
        print_error(f"perfdhcp executable not found or not executable at {args.perfdhcp_path}")
        sys.exit(1)

    client_processes_v4 = []
    client_processes_v6 = []
    client_data = []

    try:
        for i in range(args.num_clients):
            client_id = i
            ns_name = f"sim_client_ns{client_id}"
            veth_host_name = f"v_cli{client_id}_h"
            veth_ns_name = f"v_cli{client_id}_ns"

            print(f"\n--- Setting up Client {client_id} ---")
            if not setup_client_namespace(client_id, args.host_iface, veth_host_name, veth_ns_name, ns_name):
                print_error(f"Skipping client {client_id} due to setup failure.")
                client_data.append({"id": client_id, "ns_name": ns_name, "veth_host_name": veth_host_name, "setup_failed": True})
                continue
            client_data.append({"id": client_id, "ns_name": ns_name, "veth_host_name": veth_host_name, "setup_failed": False})


            if args.dhcpv4_server:
                mac_val_str = ""
                if args.base_mac:
                    try:
                        mac_parts = args.base_mac.split(':')
                        if len(mac_parts) != 6: raise ValueError("MAC must have 6 octets")
                        base_val = int(mac_parts[5], 16)
                        current_val = (base_val + client_id) % 256
                        mac_parts[5] = f"{current_val:02X}"
                        current_mac = ":".join(mac_parts)
                        mac_val_str = f"mac={current_mac}"
                    except ValueError as e:
                        print_error(f"Invalid base_mac format for client {client_id}: {args.base_mac}. Error: {e}. Omitting -b for this client.")

                v4_proc = run_perfdhcp_for_client(client_id, 4, args.dhcpv4_server, veth_ns_name,
                                                  args.rate, args.duration, args.v4_template,
                                                  args.perfdhcp_path, args.output_dir, mac_val_str, ns_name)
                if v4_proc: client_processes_v4.append(v4_proc)

            if args.dhcpv6_server:
                duid_val_str = ""
                if args.base_duid:
                    try:
                        if len(args.base_duid) > 2 and len(args.base_duid) % 2 == 0 :
                            base_hex_val = args.base_duid[:-2]
                            last_byte_hex = args.base_duid[-2:]
                            new_last_byte_val = (int(last_byte_hex, 16) + client_id) % 256
                            current_duid = f"{base_hex_val}{new_last_byte_val:02X}"
                            duid_val_str = f"duid={current_duid}"
                        elif len(args.base_duid) > 0 : # Use as is if too short to modify predictably
                             duid_val_str = f"duid={args.base_duid}"
                        else: raise ValueError("DUID cannot be empty if provided")
                    except ValueError as e:
                         print_error(f"Invalid base_duid format for client {client_id}: {args.base_duid}. Error: {e}. Omitting -b for this client.")

                v6_proc = run_perfdhcp_for_client(client_id, 6, args.dhcpv6_server, veth_ns_name,
                                                  args.rate, args.duration, args.v6_template,
                                                  args.perfdhcp_path, args.output_dir, duid_val_str, ns_name)
                if v6_proc: client_processes_v6.append(v6_proc)

            if client_processes_v4 or client_processes_v6: # Check if any process was started for this client
                 if v4_proc or v6_proc: print(f"  Client {client_id} simulation processes started.")
            else: print(f"  Client {client_id} no simulation started (check server args for v4/v6).")

        print("\nAll client simulations initiated. Waiting for completion...")

        successful_v4_sims = 0; failed_v4_sims = 0
        for proc in client_processes_v4:
            if proc:
                return_code = proc.wait()
                # Assuming client_id can be inferred or is not needed for this summary
                if return_code == 0: successful_v4_sims += 1
                else: failed_v4_sims +=1; print_error(f"A DHCPv4 perfdhcp process failed (PID {proc.pid}). Check logs.")

        successful_v6_sims = 0; failed_v6_sims = 0
        for proc in client_processes_v6:
            if proc:
                return_code = proc.wait()
                if return_code == 0: successful_v6_sims += 1
                else: failed_v6_sims +=1; print_error(f"A DHCPv6 perfdhcp process failed (PID {proc.pid}). Check logs.")

        print("\n--- Simulation Summary ---")
        if args.dhcpv4_server: print(f"DHCPv4 Simulations: {successful_v4_sims} succeeded, {failed_v4_sims} failed (out of {len(client_processes_v4)} launched).")
        if args.dhcpv6_server: print(f"DHCPv6 Simulations: {successful_v6_sims} succeeded, {failed_v6_sims} failed (out of {len(client_processes_v6)} launched).")
        print(f"Detailed logs are in: {args.output_dir}")
        print("--------------------------")

    except Exception as e:
        print_error(f"An unexpected error occurred during simulation: {e}", exc_info=True)
    finally:
        print("\n--- Cleaning up ---")
        for client_info in reversed(client_data):
            if not client_info.get("setup_failed"): # Only cleanup if setup was attempted/succeeded
                cleanup_client_namespace(client_info["id"], client_info["veth_host_name"], client_info["ns_name"])
            else:
                print(f"Skipping cleanup for client {client_info['id']} as its setup failed.")
        print("Cleanup finished.")

if __name__ == "__main__":
    main()
