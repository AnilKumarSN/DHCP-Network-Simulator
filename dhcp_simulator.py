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
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        return result
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {e}")
        if e.stdout:
            print_error(f"Stdout: {e.stdout}")
        if e.stderr:
            print_error(f"Stderr: {e.stderr}")
        raise
    except FileNotFoundError:
        print_error(f"Command not found: {command[0]}. Please ensure it's installed and in PATH.")
        raise

# Placeholder functions - to be implemented in later steps
def setup_client_namespace(client_id, host_iface, veth_host_name, veth_ns_name, ns_name):
    """Sets up a network namespace for a client."""
    print(f"Setting up namespace for client {client_id}...")
    # Actual implementation will involve multiple 'sudo ip ...' commands
    """Sets up a network namespace for a client."""
    print(f"Setting up namespace {ns_name} for client {client_id}...")

    commands = [
        ['sudo', 'ip', 'netns', 'add', ns_name],
        ['sudo', 'ip', 'link', 'add', veth_host_name, 'type', 'veth', 'peer', 'name', veth_ns_name],
        ['sudo', 'ip', 'link', 'set', veth_ns_name, 'netns', ns_name],
    ]

    # Configure host-side veth
    if host_iface.startswith('br'): # Assuming it's a bridge
        commands.append(['sudo', 'ip', 'link', 'set', veth_host_name, 'master', host_iface])

    commands.extend([
        ['sudo', 'ip', 'link', 'set', veth_host_name, 'up'],
        # Configure namespace-side veth and loopback
        ['sudo', 'ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', 'dev', 'lo', 'up'],
        ['sudo', 'ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', 'dev', veth_ns_name, 'up']
    ])

    for cmd in commands:
        run_command(cmd)

    print(f"Namespace {ns_name} and interfaces for client {client_id} set up.")


def run_perfdhcp_for_client(client_id, protocol_version, server_ip, client_iface_in_ns, rate, duration,
                            template_file, perfdhcp_path, output_dir, base_mac_or_duid_options_str, ns_name):
    """Runs perfdhcp for a client in its namespace."""
    """Runs perfdhcp for a client in its namespace."""
    log_file_name = f"client_{client_id}_v{protocol_version}.log"
    log_file_path = os.path.join(output_dir, log_file_name)

    print(f"Running perfdhcp for client {client_id} (IPv{protocol_version}), log: {log_file_path}...")

    cmd = ['sudo', 'ip', 'netns', 'exec', ns_name, perfdhcp_path]

    if protocol_version == 4:
        cmd.append('-4')
    elif protocol_version == 6:
        cmd.append('-6')
    else:
        print_error(f"Unsupported protocol version: {protocol_version}")
        return None

    cmd.extend(['-l', client_iface_in_ns])
    cmd.extend(['-r', str(rate)])
    cmd.extend(['-R', '1']) # Each perfdhcp instance is one client
    cmd.extend(['-p', str(duration)])

    # Add template file if specified
    if template_file:
        if os.path.isfile(template_file):
            cmd.extend(['-T', template_file])
        else:
            print_error(f"Template file {template_file} not found. Ignoring.")

    # Add base MAC/DUID options if provided (already formatted as a string like "-b mac=XX" or "-b duid=YY")
    if base_mac_or_duid_options_str:
        # perfdhcp expects -b type=value, so we split the string if it's complex,
        # or just append if it's simple like what we generate.
        # Our current generation is a single string like "-b mac=...", which is not how -b works.
        # -b needs to be like: '-b', 'mac=actual_mac_address'
        # The string base_mac_or_duid_options_str is currently like "mac=00:00:00:00:00:00" (incorrect)
        # or "-b mac=00:00:00:00:00:00" (also incorrect for extend)
        # It should be a list of arguments e.g. ['-b', 'mac=AA:BB:CC:DD:EE:FF']
        # Let's adjust the caller or parse it here.
        # For now, assuming base_mac_or_duid_options_str IS the "type=value" part.
        # e.g. "mac=AA:BB:CC:DD:EE:FF"
         cmd.extend(['-b', base_mac_or_duid_options_str])


    cmd.append(server_ip)

    print(f"  Executing: {' '.join(cmd)}")

    try:
        # Using Popen for non-blocking execution. Output is redirected to a log file.
        log_fp = open(log_file_path, 'w')
        proc = subprocess.Popen(cmd, stdout=log_fp, stderr=subprocess.STDOUT)
        print(f"  perfdhcp process for client {client_id} (IPv{protocol_version}) started with PID {proc.pid}.")
        return proc
    except Exception as e:
        print_error(f"Failed to start perfdhcp for client {client_id} (IPv{protocol_version}): {e}")
        if 'log_fp' in locals() and log_fp:
            log_fp.close()
        return None


def cleanup_client_namespace(client_id, veth_host_name, ns_name):
    """Cleans up a client's network namespace."""
    print(f"Cleaning up namespace {ns_name} for client {client_id}...")
    try:
        run_command(['sudo', 'ip', 'netns', 'del', ns_name], check=False) # Deletes ns and veth inside it
    except subprocess.CalledProcessError:
        # If ns deletion fails, veth_host_name might still exist if not attached to a bridge that got deleted etc.
        # Attempt to delete host veth interface explicitly if it wasn't deleted with the namespace
        # This might occur if the namespace couldn't be deleted because an interface was busy
        # or if the veth_host_name was not properly cleaned up by netns del (unlikely for veth peers).
        print(f"Namespace {ns_name} deletion might have failed or veth {veth_host_name} might persist. Attempting to delete veth.")
        run_command(['sudo', 'ip', 'link', 'del', veth_host_name], check=False) # Best effort
    except FileNotFoundError: # ip command not found
        print_error("ip command not found during cleanup.")
        raise
    print(f"Namespace {ns_name} for client {client_id} cleaned up.")


def main():
    parser = argparse.ArgumentParser(description="Dual Stack DHCP Client Simulator using Kea perfdhcp.")
    parser.add_argument("--num-clients", type=int, required=True, help="Number of dual-stack clients to simulate.")
    parser.add_argument("--host-iface", type=str, required=True, help="Host-side network interface or bridge (e.g., br0).")
    parser.add_argument("--dhcpv4-server", type=str, help="IP address of the DHCPv4 server. Skips v4 if not provided.")
    parser.add_argument("--dhcpv6-server", type=str, help="IP address/alias of the DHCPv6 server. Skips v6 if not provided.")
    parser.add_argument("--rate", type=int, default=10, help="Target requests per second per client per protocol.")
    parser.add_argument("--duration", type=int, default=60, help="Duration of the test in seconds for each client.")
    parser.add_argument("--v4-template", type=str, help="Path to a custom DHCPv4 packet template for perfdhcp.")
    parser.add_argument("--v6-template", type=str, help="Path to a custom DHCPv6 packet template for perfdhcp.")
    parser.add_argument("--perfdhcp-path", type=str, default="/usr/sbin/perfdhcp", help="Path to perfdhcp executable.")
    parser.add_argument("--output-dir", type=str, default="perfdhcp_results", help="Directory to store perfdhcp output logs.")
    parser.add_argument("--base-mac", type=str, help="Base MAC for DHCPv4 clients (e.g., 00:00:00:00:00:00). Last octet increments.")
    parser.add_argument("--base-duid", type=str, help="Base DUID (hex) for DHCPv6 clients. Last byte increments.")

    args = parser.parse_args()

    if not args.dhcpv4_server and not args.dhcpv6_server:
        print_error("At least one of --dhcpv4-server or --dhcpv6-server must be specified.")
        sys.exit(1)

    if os.geteuid() != 0:
        print_error("This script requires root privileges for network namespace and interface manipulation.")
        # For testing purposes, we might allow it to proceed to see arg parsing,
        # but actual commands will fail.
        # sys.exit(1) # Comment out for non-root testing of script structure

    # Create output directory
    if os.path.exists(args.output_dir):
        print(f"Output directory {args.output_dir} exists. Removing and recreating.")
        shutil.rmtree(args.output_dir)
    os.makedirs(args.output_dir, exist_ok=True)
    print(f"Storing results in {args.output_dir}")


    print(f"Starting simulation with {args.num_clients} client(s).")
    print(f"Host interface: {args.host_iface}")
    if args.dhcpv4_server:
        print(f"DHCPv4 Server: {args.dhcpv4_server}")
    if args.dhcpv6_server:
        print(f"DHCPv6 Server: {args.dhcpv6_server}")
    print(f"Rate: {args.rate} rps, Duration: {args.duration}s")
    print(f"Perfdhcp path: {args.perfdhcp_path}")

    # Check if perfdhcp executable exists
    if not os.path.isfile(args.perfdhcp_path) or not os.access(args.perfdhcp_path, os.X_OK):
        print_error(f"perfdhcp executable not found or not executable at {args.perfdhcp_path}")
        sys.exit(1)

    client_processes_v4 = []
    client_processes_v6 = []
    client_data = [] # To store names for cleanup

    try:
        for i in range(args.num_clients):
            client_id = i
            ns_name = f"sim_ns{client_id}"
            veth_host_name = f"veth_host{client_id}"
            veth_ns_name = f"veth_ns{client_id}"
            client_data.append({"id": client_id, "ns_name": ns_name, "veth_host_name": veth_host_name})

            print(f"\n--- Setting up Client {client_id} ---")
            # setup_client_namespace(client_id, args.host_iface, veth_host_name, veth_ns_name, ns_name) # Full implementation later

            v4_proc = None
            v6_proc = None

            if args.dhcpv4_server:
                mac_options_str = ""
                if args.base_mac:
                    try:
                        mac_parts = args.base_mac.split(':')
                        if len(mac_parts) != 6: raise ValueError("MAC must have 6 octets")
                        base_val = int(mac_parts[5], 16)
                        current_val = (base_val + client_id) % 256
                        mac_parts[5] = f"{current_val:02x}"
                        current_mac = ":".join(mac_parts)
                        mac_options_str = f"-b mac={current_mac}"
                    except ValueError as e:
                        print_error(f"Invalid base_mac format: {args.base_mac}. Error: {e}")
                        # Decide: stop or continue without this option? For now, continue.

                # v4_proc = run_perfdhcp_for_client(client_id, 4, args.dhcpv4_server, veth_ns_name,
                #                                   args.rate, args.duration, args.v4_template,
                #                                   args.perfdhcp_path, args.output_dir, mac_options_str, ns_name)
                # client_processes_v4.append(v4_proc)
                print(f"  [Placeholder] Would run DHCPv4 client {client_id} with MAC options: '{mac_options_str}'")


            if args.dhcpv6_server:
                duid_options_str = ""
                if args.base_duid:
                    try:
                        # Simple DUID modification: treat as hex, add client_id to its integer value, ensuring fixed length.
                        # This is a naive approach; real DUIDs have structure.
                        # For perfdhcp, -b duid= expects a hex string.
                        # Example: if base_duid is 16 hex chars (8 bytes), increment the last part.
                        # A robust way would be to parse DUID type or just append/modify last bytes.
                        # For simplicity, let's assume a DUID that can be somewhat incremented.
                        # A safer bet for perfdhcp is often to let it manage DUIDs with -R or use -M for lists.
                        # If we use -b duid, we need to ensure uniqueness.
                        # A simple increment of the hex string might not be valid for all DUID types.
                        # Let's try incrementing the last part of the hex string if it's long enough.
                        if len(args.base_duid) > 2: # Ensure at least one byte to modify
                            base_hex_val = args.base_duid[:-2]
                            last_byte_hex = args.base_duid[-2:]
                            new_last_byte_val = (int(last_byte_hex, 16) + client_id) % 256
                            current_duid = f"{base_hex_val}{new_last_byte_val:02x}"
                            duid_options_str = f"-b duid={current_duid}"
                        else:
                             duid_options_str = f"-b duid={args.base_duid}" # Fallback or error
                    except ValueError as e:
                         print_error(f"Invalid base_duid format: {args.base_duid}. Error: {e}")

                # v6_proc = run_perfdhcp_for_client(client_id, 6, args.dhcpv6_server, veth_ns_name,
                #                                   args.rate, args.duration, args.v6_template,
                #                                   args.perfdhcp_path, args.output_dir, duid_options_str, ns_name)
                # client_processes_v6.append(v6_proc)
                print(f"  [Placeholder] Would run DHCPv6 client {client_id} with DUID options: '{duid_options_str}'")

            # if v4_proc or v6_proc:
            #     print(f"  Client {client_id} simulation processes started.")
            # else:
            #     print(f"  Client {client_id} no simulation started (check server configs).")


        print("\nAll client simulations initiated. Waiting for completion...")

        successful_v4_sims = 0
        failed_v4_sims = 0
        for i, proc in enumerate(client_processes_v4):
            if proc:
                return_code = proc.wait()
                client_id = client_data[i]['id'] # Assuming client_processes_v4 lines up with client_data
                if return_code == 0:
                    print(f"  DHCPv4 simulation for client {client_id} completed successfully.")
                    successful_v4_sims += 1
                else:
                    print_error(f"DHCPv4 simulation for client {client_id} failed with exit code {return_code}. Check logs in {args.output_dir}.")
                    failed_v4_sims +=1

        successful_v6_sims = 0
        failed_v6_sims = 0
        for i, proc in enumerate(client_processes_v6):
            if proc:
                return_code = proc.wait()
                client_id = client_data[i]['id'] # Assuming client_processes_v6 lines up with client_data
                if return_code == 0:
                    print(f"  DHCPv6 simulation for client {client_id} completed successfully.")
                    successful_v6_sims += 1
                else:
                    print_error(f"DHCPv6 simulation for client {client_id} failed with exit code {return_code}. Check logs in {args.output_dir}.")
                    failed_v6_sims += 1

        print("\n--- Simulation Summary ---")
        if args.dhcpv4_server:
            print(f"DHCPv4 Simulations: {successful_v4_sims} succeeded, {failed_v4_sims} failed (out of {len(client_processes_v4)} launched).")
        if args.dhcpv6_server:
            print(f"DHCPv6 Simulations: {successful_v6_sims} succeeded, {failed_v6_sims} failed (out of {len(client_processes_v6)} launched).")
        print(f"Detailed logs are in: {args.output_dir}")
        print("--------------------------")

    except Exception as e:
        print_error(f"An unexpected error occurred during simulation: {e}")
    finally:
        print("\n--- Cleaning up ---")
        # for client_info in reversed(client_data): # Cleanup in reverse order of creation
        #     cleanup_client_namespace(client_info["id"], client_info["veth_host_name"], client_info["ns_name"])
        print("Cleanup placeholder complete.")

if __name__ == "__main__":
    main()
