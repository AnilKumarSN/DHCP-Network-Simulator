#!/bin/bash

# Script to set up Kea DHCPv4 and DHCPv6 servers in RED and BLUE namespaces,
# each with multiple subnets and pools.

# Global variables (adjust as needed)
BRIDGE_NAME="br_dhcp_test" # Main bridge for Kea server server-facing connections
BR_CLIENTS_NAME="br_clients" # Bridge for all clients and the Python relay's client-facing interface

KEA_BIN_DIR="/usr/sbin" # Assuming Kea executables are here
KEA_DHCP4_BIN="${KEA_BIN_DIR}/kea-dhcp4"
KEA_DHCP6_BIN="${KEA_BIN_DIR}/kea-dhcp6"
# DHCRELAY_BIN="/usr/sbin/dhcrelay" # No longer using isc-dhcp-relay
PYTHON_RELAY_SCRIPT_PATH="./dhcp_pyrelay.py" # Path to our custom Python relay

# Runtime directories
KEA_RUNTIME_BASE_DIR="/tmp/kea_rt"
RED_NS_RUNTIME_DIR="${KEA_RUNTIME_BASE_DIR}/ns_red"
BLUE_NS_RUNTIME_DIR="${KEA_RUNTIME_BASE_DIR}/ns_blue"
PYRELAY_NS_RUNTIME_DIR="${KEA_RUNTIME_BASE_DIR}/ns_pyrelay" # For Python relay agent


# --- Logging functions ---
log_info() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2
}

# --- Utility functions ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root or with sudo."
        exit 1
    fi
}

# --- Network functions ---
create_bridge_if_not_exists() {
    local bridge_name="$1"
    if ! ip link show "$bridge_name" > /dev/null 2>&1; then
        log_info "Creating bridge $bridge_name..."
        sudo ip link add name "$bridge_name" type bridge || { log_error "Failed to create bridge $bridge_name"; exit 1; }
        sudo ip link set dev "$bridge_name" up || { log_error "Failed to bring up bridge $bridge_name"; exit 1; }
    else
        log_info "Bridge $bridge_name already exists."
    fi
}

setup_namespace() {
    local ns_name="$1"
    local veth_host="$2"
    local veth_ns="$3"
    local ns_ip4_primary="$4" # e.g., 192.168.10.1/24
    local ns_ip4_secondary="$5" # e.g., 192.168.11.1/24 or empty
    local ns_ip6_primary="$6" # e.g., fd00:red::1/64
    local ns_ip6_secondary="$7" # e.g., fd00:red:1::1/64 or empty
    local bridge_name="$8"

    log_info "Setting up namespace $ns_name..."
    sudo ip netns add "$ns_name" || { log_error "Failed to add namespace $ns_name"; exit 1; }
    sudo ip link add name "$veth_host" type veth peer name "$veth_ns" || { log_error "Failed to create veth pair for $ns_name"; exit 1; }
    sudo ip link set "$veth_ns" netns "$ns_name" || { log_error "Failed to move $veth_ns to $ns_name"; exit 1; }
    sudo ip link set "$veth_host" master "$bridge_name" || { log_error "Failed to attach $veth_host to bridge $bridge_name"; exit 1; }
    sudo ip link set "$veth_host" up || { log_error "Failed to bring up $veth_host"; exit 1; }

    sudo ip netns exec "$ns_name" ip link set dev lo up
    sudo ip netns exec "$ns_name" ip link set dev "$veth_ns" up
    sudo ip netns exec "$ns_name" ip addr add "$ns_ip4_primary" dev "$veth_ns" || { log_error "Failed to add primary IPv4 $ns_ip4_primary to $veth_ns in $ns_name"; exit 1; }
    if [ -n "$ns_ip4_secondary" ]; then
        sudo ip netns exec "$ns_name" ip addr add "$ns_ip4_secondary" dev "$veth_ns" || { log_error "Failed to add secondary IPv4 $ns_ip4_secondary to $veth_ns in $ns_name"; exit 1; }
    fi
    sudo ip netns exec "$ns_name" ip -6 addr add "$ns_ip6_primary" dev "$veth_ns" || { log_error "Failed to add primary IPv6 $ns_ip6_primary to $veth_ns in $ns_name"; exit 1; }
     if [ -n "$ns_ip6_secondary" ]; then
        sudo ip netns exec "$ns_name" ip -6 addr add "$ns_ip6_secondary" dev "$veth_ns" || { log_error "Failed to add secondary IPv6 $ns_ip6_secondary to $veth_ns in $ns_name"; exit 1; }
    fi
    log_info "Namespace $ns_name configured with veth $veth_ns (IPs: $ns_ip4_primary, $ns_ip6_primary, etc.) and $veth_host attached to $bridge_name."
}

create_kea_config_dirs() {
    log_info "Creating Kea runtime directories..."
    sudo mkdir -p "$RED_NS_RUNTIME_DIR" "$BLUE_NS_RUNTIME_DIR"
    # In a real scenario, ensure appropriate ownership/permissions for Kea user
    # For this script, running Kea as root (via sudo ip netns exec) will bypass some permission issues.
    sudo chmod -R 777 "${KEA_RUNTIME_BASE_DIR}" # Simplistic for now
    log_info "Kea runtime directories created: $RED_NS_RUNTIME_DIR, $BLUE_NS_RUNTIME_DIR"
}

# --- Kea Config Generation (stubs for now) ---
generate_kea_dhcp4_config() {
    local ns_name="$1"
    local conf_file_path="$2"
    local lease_file_path="$3"
    local interface_name="$4"
    local subnet1_cidr="$5" # e.g. 192.168.10.0/24
    local pool1_range="$6"  # e.g. 192.168.10.100 - 192.168.10.150
    local subnet2_cidr="$7"
    local pool2_range="$8"
    local control_socket_path="$9" # e.g. /tmp/kea_rt/ns_red/kea-dhcp4.sock

    log_info "Generating Kea DHCPv4 config for $ns_name at $conf_file_path..."
    # Actual JSON generation will be here
    cat << EOF > "$conf_file_path"
{
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": ["$interface_name"]
        },
        "lease-database": {
            "type": "memfile",
            "lfc-interval": 3600,
            "name": "$lease_file_path"
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "$control_socket_path"
        },
        "loggers": [{
            "name": "kea-dhcp4",
            "output_options": [{"output": "stdout"}],
            "severity": "INFO",
            "debuglevel": 0
        }],
        "shared-networks": [
            {
                "name": "shared_net_${ns_name}_v4",
                "interface": "$interface_name", // Kea will listen on this interface for this shared network
                                               // The IP addresses on this interface will help Kea identify the shared network
                                               // if multiple shared-networks are defined on different interfaces.
                "subnet4": [
                    {
                        "subnet": "$subnet1_cidr",
                        "pools": [ { "pool": "$pool1_range" } ],
                        "option-data": [ { "name": "routers", "data": "${subnet1_cidr%.*}.1" } ]
                    },
                    {
                        "subnet": "$subnet2_cidr",
                        "pools": [ { "pool": "$pool2_range" } ],
                        "option-data": [ { "name": "routers", "data": "${subnet2_cidr%.*}.1" } ]
                    }
                ]
            }
        ]
    }
}
EOF
    log_info "Generated Kea DHCPv4 config for $ns_name."
}

generate_kea_dhcp6_config() {
    local ns_name="$1"
    local conf_file_path="$2"
    local lease_file_path="$3"
    local interface_name="$4"
    local subnet1_prefix="$5" # e.g. fd00:red::/64
    local pool1_range="$6"    # e.g. fd00:red::100 - fd00:red::1ff
    local subnet2_prefix="$7"
    local pool2_range="$8"
    local control_socket_path="$9"

    log_info "Generating Kea DHCPv6 config for $ns_name at $conf_file_path..."
    cat << EOF > "$conf_file_path"
{
    "Dhcp6": {
        "interfaces-config": {
            "interfaces": ["$interface_name"] // Kea needs to know which physical interface to listen on
        },
        "lease-database": {
            "type": "memfile",
            "lfc-interval": 3600,
            "name": "$lease_file_path"
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "$control_socket_path"
        },
        "loggers": [{
            "name": "kea-dhcp6",
            "output_options": [{"output": "stdout"}],
            "severity": "INFO",
            "debuglevel": 0
        }],
        "shared-networks": [
            {
                "name": "shared_net_${ns_name}_v6",
                "interface": "$interface_name", // Optional here if already globally defined in interfaces-config and unambiguous.
                                               // However, explicit is good.
                "subnet6": [
                    {
                        "subnet": "$subnet1_prefix",
                        "pools": [ { "pool": "$pool1_range" } ]
                        // Routers option for DHCPv6 is typically done via RA, not DHCPv6 options,
                        // unless specific (like OPTION_DNS_SERVERS).
                        // For IA_NA, clients use the link-local address of the router.
                    },
                    {
                        "subnet": "$subnet2_prefix",
                        "pools": [ { "pool": "$pool2_range" } ]
                    }
                ]
            }
        ]
    }
}
EOF
    log_info "Generated Kea DHCPv6 config for $ns_name."
}


# --- Kea Server Management (stubs for now) ---
start_kea_server() {
    local ns_name="$1"
    local protocol="$2" # "dhcp4" or "dhcp6"
    local conf_file_path="$3"
    local kea_bin=""
    local pid_file=""

    if [ "$protocol" == "dhcp4" ]; then
        kea_bin="$KEA_DHCP4_BIN"
        pid_file="${KEA_RUNTIME_BASE_DIR}/${ns_name}/kea-dhcp4.pid"
    elif [ "$protocol" == "dhcp6" ]; then
        kea_bin="$KEA_DHCP6_BIN"
        pid_file="${KEA_RUNTIME_BASE_DIR}/${ns_name}/kea-dhcp6.pid"
    else
        log_error "Unknown protocol $protocol for starting Kea server."
        return 1
    fi

    log_info "Starting Kea $protocol server in namespace $ns_name with config $conf_file_path..."
    # The & must be inside the sudo ip netns exec command's context if we want the PID of kea-dhcp, not ip netns.
    # However, getting the PID correctly from a backgrounded process within ip netns exec is tricky.
    # Kea itself can write a PID file if configured, but that's not in the default config.
    # For simplicity, we'll run it in foreground for now within a subshell for start_all, or manage PIDs externally.
    # Let's create a wrapper for ip netns exec that handles PID.

    # Simple start (foreground for now in terms of script logic, backgrounded manually by start_all)
    # sudo ip netns exec "$ns_name" "$kea_bin" -c "$conf_file_path" &
    # echo $! > "$pid_file" # This would capture PID of ip netns exec, not kea-dhcp.

    # To capture the actual Kea process PID, we can use a helper script or complex exec.
    # Or, rely on pgrep for stopping.
    # For now, let's assume we run it and it backgrounds itself if it's a daemon, or we manage it.
    # Kea daemons run in foreground by default unless they fork.
    # The -d option for Kea makes it run in the background (daemonize).
    # However, there is no -d option for kea-dhcp4/6 directly. `keactrl` handles daemonizing.
    # We will run them in foreground and background the `ip netns exec` call.

    # Create a log file for the server's stdout/stderr
    local log_file="${KEA_RUNTIME_BASE_DIR}/${ns_name}/kea-${protocol}-server.log"
    sudo ip netns exec "$ns_name" "$kea_bin" -c "$conf_file_path" > "$log_file" 2>&1 &
    # Store the PID of the backgrounded 'ip netns exec' command. This is not the Kea PID itself.
    echo $! > "$pid_file"

    # Wait a moment for the server to start or fail
    sleep 2
    if ps -p "$(cat $pid_file)" > /dev/null; then
        log_info "Kea $protocol server in $ns_name started (process group PID $(cat $pid_file)). Log: $log_file"
    else
        log_error "Kea $protocol server in $ns_name failed to start. Check log: $log_file"
        cat "$log_file"
        return 1
    fi
}

stop_kea_server() {
    local ns_name="$1"
    local protocol="$2" # "dhcp4" or "dhcp6"
    local pid_file_path=""

    if [ "$protocol" == "dhcp4" ]; then
        pid_file_path="${KEA_RUNTIME_BASE_DIR}/${ns_name}/kea-dhcp4.pid"
    elif [ "$protocol" == "dhcp6" ]; then
        pid_file_path="${KEA_RUNTIME_BASE_DIR}/${ns_name}/kea-dhcp6.pid"
    else
        log_error "Unknown protocol $protocol for stopping Kea server."
        return 1
    fi

    if [ -f "$pid_file_path" ]; then
        local pgid
        pgid=$(cat "$pid_file_path")
        if ps -p "$pgid" > /dev/null; then
            log_info "Stopping Kea $protocol server in $ns_name (PGID $pgid)..."
            # Kill the process group started by `ip netns exec ... &`
            sudo kill -TERM "-$pgid" # Kill process group
            sleep 1
            # Check if it's still running
            if ps -p "$pgid" > /dev/null; then
                log_info "Kea $protocol server in $ns_name (PGID $pgid) still running, sending SIGKILL..."
                sudo kill -KILL "-$pgid"
            fi
            sudo rm -f "$pid_file_path"
            log_info "Kea $protocol server in $ns_name stopped."
        else
            log_info "Kea $protocol server in $ns_name (PGID $pgid) not running or PID file stale."
            sudo rm -f "$pid_file_path"
        fi
    else
        log_info "PID file $pid_file_path not found for Kea $protocol server in $ns_name. Maybe not started or already stopped."
        # Fallback: try to find by name if PID file is missing
        # This is risky if other kea processes are running.
        # Example: sudo ip netns exec "$ns_name" pkill -f "kea-dhcp4 -c.*${ns_name}"
    fi
}

# --- Cleanup functions (stubs for now) ---
cleanup_namespace_full() {
    local ns_name="$1"
    local veth_host="$2"
    log_info "Cleaning up namespace $ns_name and veth $veth_host..."
    if ip netns list | grep -q "$ns_name"; then
        sudo ip netns del "$ns_name" || log_error "Failed to delete namespace $ns_name (maybe it's busy or interfaces still exist)."
    else
        log_info "Namespace $ns_name does not exist."
    fi
    # veth_host is deleted automatically when namespace is deleted if it's a veth peer.
    # If it was attached to a bridge, it might need explicit deletion if not handled by ns del.
    if ip link show "$veth_host" > /dev/null 2>&1; then
         sudo ip link del "$veth_host" || log_error "Failed to delete veth $veth_host."
    fi
}

cleanup_bridge() {
    local bridge_name="$1"
    if ip link show "$bridge_name" > /dev/null 2>&1; then
        log_info "Cleaning up bridge $bridge_name..."
        sudo ip link set dev "$bridge_name" down || log_error "Failed to bring down bridge $bridge_name."
        sudo ip link del dev "$bridge_name" || log_error "Failed to delete bridge $bridge_name."
    else
        log_info "Bridge $bridge_name does not exist."
    fi
}

cleanup_runtime_dirs() {
    log_info "Cleaning up runtime directories under $KEA_RUNTIME_BASE_DIR..."
    sudo rm -rf "$KEA_RUNTIME_BASE_DIR"
}

# --- Main actions ---
action_start() {
    log_info "=== Starting Kea Server Setup ==="
    check_root
    create_bridge_if_not_exists "$BRIDGE_NAME"
    create_kea_config_dirs

    # Setup RED Namespace and Servers
    setup_namespace "ns_red" "veth_red_host" "veth_red_ns" \
        "192.168.10.1/24" "192.168.11.1/24" \
        "fd00:red::1/64" "fd00:red:1::1/64" \
        "$BRIDGE_NAME"

    generate_kea_dhcp4_config "ns_red" "${RED_NS_RUNTIME_DIR}/kea-dhcp4-red.conf" \
        "${RED_NS_RUNTIME_DIR}/kea-leases4.csv" "veth_red_ns" \
        "192.168.10.0/24" "192.168.10.100 - 192.168.10.150" \
        "192.168.11.0/24" "192.168.11.100 - 192.168.11.150" \
        "${RED_NS_RUNTIME_DIR}/kea-dhcp4.sock"
    start_kea_server "ns_red" "dhcp4" "${RED_NS_RUNTIME_DIR}/kea-dhcp4-red.conf"

    generate_kea_dhcp6_config "ns_red" "${RED_NS_RUNTIME_DIR}/kea-dhcp6-red.conf" \
        "${RED_NS_RUNTIME_DIR}/kea-leases6.csv" "veth_red_ns" \
        "fd00:red::/64" "fd00:red::100 - fd00:red::1ff" \
        "fd00:red:1::/64" "fd00:red:1::100 - fd00:red:1::1ff" \
        "${RED_NS_RUNTIME_DIR}/kea-dhcp6.sock"
    start_kea_server "ns_red" "dhcp6" "${RED_NS_RUNTIME_DIR}/kea-dhcp6-red.conf"

    # Setup BLUE Namespace and Servers
    setup_namespace "ns_blue" "veth_blue_host" "veth_blue_ns" \
        "192.168.20.1/24" "192.168.21.1/24" \
        "fd00:blue::1/64" "fd00:blue:1::1/64" \
        "$BRIDGE_NAME"

    generate_kea_dhcp4_config "ns_blue" "${BLUE_NS_RUNTIME_DIR}/kea-dhcp4-blue.conf" \
        "${BLUE_NS_RUNTIME_DIR}/kea-leases4.csv" "veth_blue_ns" \
        "192.168.20.0/24" "192.168.20.100 - 192.168.20.150" \
        "192.168.21.0/24" "192.168.21.100 - 192.168.21.150" \
        "${BLUE_NS_RUNTIME_DIR}/kea-dhcp4.sock"
    start_kea_server "ns_blue" "dhcp4" "${BLUE_NS_RUNTIME_DIR}/kea-dhcp4-blue.conf"

    generate_kea_dhcp6_config "ns_blue" "${BLUE_NS_RUNTIME_DIR}/kea-dhcp6-blue.conf" \
        "${BLUE_NS_RUNTIME_DIR}/kea-leases6.csv" "veth_blue_ns" \
        "fd00:blue::/64" "fd00:blue::100 - fd00:blue::1ff" \
        "fd00:blue:1::/64" "fd00:blue:1::100 - fd00:blue:1::1ff" \
        "${BLUE_NS_RUNTIME_DIR}/kea-dhcp6.sock"
    start_kea_server "ns_blue" "dhcp6" "${BLUE_NS_RUNTIME_DIR}/kea-dhcp6-blue.conf"

    log_info "All Kea servers started. Check logs in $KEA_RUNTIME_BASE_DIR/*/*.log"
    log_info "To test, create a client namespace, connect it to $BRIDGE_NAME, and run dhclient."
    log_info "Example client setup:"
    log_info " sudo ip netns add ns_client"
    log_info " sudo ip link add v_cli_h type veth peer name v_cli_ns"
    log_info " sudo ip link set v_cli_ns netns ns_client"
    log_info " sudo ip link set v_cli_h master $BRIDGE_NAME"
    log_info " sudo ip link set v_cli_h up"
    log_info " sudo ip netns exec ns_client ip link set dev lo up"
    log_info " sudo ip netns exec ns_client ip link set dev v_cli_ns up"
    log_info " sudo ip netns exec ns_client dhclient -4 -v v_cli_ns  # For DHCPv4"
    log_info " sudo ip netns exec ns_client dhclient -6 -v v_cli_ns  # For DHCPv6"
    log_info " (Remember to release lease and cleanup client ns: sudo ip netns exec ns_client dhclient -r v_cli_ns; sudo ip netns del ns_client)"
}

action_stop() {
    log_info "=== Stopping Kea Servers ==="
    check_root
    stop_kea_server "ns_red" "dhcp4"
    stop_kea_server "ns_red" "dhcp6"
    stop_kea_server "ns_blue" "dhcp4"
    stop_kea_server "ns_blue" "dhcp6"
    log_info "All Kea servers stopped."
}

action_cleanup() {
    log_info "=== Cleaning Up Environment ==="
    check_root
    action_stop # Ensure servers are stopped first

    cleanup_namespace_full "ns_red" "veth_red_host"
    cleanup_namespace_full "ns_blue" "veth_blue_host"
    cleanup_bridge "$BRIDGE_NAME"
    cleanup_runtime_dirs
    log_info "Cleanup complete."
}

action_status() {
    log_info "=== Kea Server Status ==="
    check_root
    for ns in ns_red ns_blue; do
        for proto in dhcp4 dhcp6; do
            pid_file="${KEA_RUNTIME_BASE_DIR}/${ns}/kea-${proto}.pid"
            if [ -f "$pid_file" ]; then
                pgid=$(cat "$pid_file")
                if ps -p "$pgid" > /dev/null; then
                    log_info "Kea $proto server in $ns is RUNNING (PGID $pgid)."
                    # Show associated Kea process (this might be complex if Kea forks internally)
                    # We check the children of the 'ip netns exec' command.
                    # sudo ip netns exec "$ns" ps aux | grep -E "kea-${proto}.*-c.*${ns}" | grep -v grep
                else
                    log_info "Kea $proto server in $ns is STOPPED (stale PID file $pid_file)."
                fi
            else
                log_info "Kea $proto server in $ns is STOPPED (no PID file)."
            fi
        done
    done
}


# --- Main script logic ---
if [ -z "$1" ]; then
    echo "Usage: $0 <start|stop|restart|status|cleanup>"
    exit 1
fi

case "$1" in
    start)
        action_start
        ;;
    stop)
        action_stop
        ;;
    restart)
        action_stop
        sleep 2
        action_start
        ;;
    status)
        action_status
        ;;
    cleanup)
        action_cleanup
        ;;
    *)
        echo "Invalid action: $1"
        echo "Usage: $0 <start|stop|restart|status|cleanup>"
        exit 1
        ;;
esac

exit 0
