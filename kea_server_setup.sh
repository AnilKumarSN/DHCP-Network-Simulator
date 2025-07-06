#!/bin/bash

# Script to set up Kea DHCPv4 and DHCPv6 servers in RED and BLUE namespaces,
# and a Python-based DHCP relay agent in its own namespace.

# --- Global variables ---
BRIDGE_NAME="br_dhcp_test" # Main bridge for Kea server and relay server-facing connections
BR_CLIENTS_NAME="br_clients" # Bridge for all clients and the Python relay's client-facing interface

KEA_BIN_DIR="/usr/sbin"
KEA_DHCP4_BIN="${KEA_BIN_DIR}/kea-dhcp4"
KEA_DHCP6_BIN="${KEA_BIN_DIR}/kea-dhcp6"
PYTHON_RELAY_SCRIPT_PATH="./dhcp_pyrelay.py" # Path to our custom Python relay

KEA_RUNTIME_BASE_DIR="/tmp/kea_rt"
RED_NS_RUNTIME_DIR="${KEA_RUNTIME_BASE_DIR}/ns_red"
BLUE_NS_RUNTIME_DIR="${KEA_RUNTIME_BASE_DIR}/ns_blue"
PYRELAY_NS_RUNTIME_DIR="${KEA_RUNTIME_BASE_DIR}/ns_pyrelay"

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

check_python_installation() {
    if ! command -v python3 &> /dev/null; then
        log_error "python3 could not be found."
        log_error "Please install Python 3 as it is required for the custom DHCP relay agent."
        exit 1
    fi
    log_info "Python 3 found."
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

# Setup for Kea Server Namespaces
setup_server_namespace() {
    local ns_name="$1"
    local veth_host="$2"
    local veth_ns="$3"
    local ns_ip4_primary="$4"
    local ns_ip4_secondary="$5"
    local ns_ip6_primary="$6"
    local ns_ip6_secondary="$7"
    local bridge_name="$8"

    log_info "Setting up Kea server namespace $ns_name..."
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

    # Primary IPv6
    local ip6_primary_addr_only
    ip6_primary_addr_only=$(echo "$ns_ip6_primary" | cut -d'/' -f1)
    sudo ip netns exec "$ns_name" bash -c "ip -6 addr add '${ip6_primary_addr_only}/128' dev '${veth_ns}'" || { log_error "Failed to add primary IPv6 address ${ip6_primary_addr_only}/128 to $veth_ns in $ns_name"; exit 1; }
    sudo ip netns exec "$ns_name" bash -c "ip -6 route add '${ns_ip6_primary}' dev '${veth_ns}'" || { log_error "Failed to add primary IPv6 route $ns_ip6_primary via $veth_ns in $ns_name"; exit 1; }

     if [ -n "$ns_ip6_secondary" ]; then
        local ip6_secondary_addr_only
        ip6_secondary_addr_only=$(echo "$ns_ip6_secondary" | cut -d'/' -f1)
        sudo ip netns exec "$ns_name" bash -c "ip -6 addr add '${ip6_secondary_addr_only}/128' dev '${veth_ns}'" || { log_error "Failed to add secondary IPv6 address ${ip6_secondary_addr_only}/128 to $veth_ns in $ns_name"; exit 1; }
        sudo ip netns exec "$ns_name" bash -c "ip -6 route add '${ns_ip6_secondary}' dev '${veth_ns}'" || { log_error "Failed to add secondary IPv6 route $ns_ip6_secondary via $veth_ns in $ns_name"; exit 1; }
    fi
    log_info "Namespace $ns_name configured with veth $veth_ns and $veth_host attached to $bridge_name."
}

# Setup for Python Relay Namespace
setup_pyrelay_namespace() {
    local ns_name="ns_pyrelay"
    local veth_host_c="v_pyrelay_c_h"
    local veth_ns_c="v_pyrelay_c_ns"
    local client_bridge="$BR_CLIENTS_NAME"
    local client_ips_array_str="192.168.10.254/24 192.168.11.254/24 192.168.20.254/24 192.168.21.254/24 fd00:red::fe/64 fd00:red:1::fe/64 fd00:blue::fe/64 fd00:blue:1::fe/64"

    local veth_host_s="v_pyrelay_s_h"
    local veth_ns_s="v_pyrelay_s_ns"
    local server_bridge="$BRIDGE_NAME"
    local server_ips_array_str="192.168.100.50/24 fd00:main::50/64"

    log_info "Setting up Python relay namespace $ns_name..."
    sudo ip netns add "$ns_name" || { log_error "Failed to add namespace $ns_name"; exit 1; }

    # Client-facing interface
    log_info "Configuring client-facing interface $veth_ns_c for $ns_name on $client_bridge..."
    sudo ip link add name "$veth_host_c" type veth peer name "$veth_ns_c" || { log_error "Failed to create client-facing veth for $ns_name"; exit 1; }
    sudo ip link set "$veth_ns_c" netns "$ns_name" || { log_error "Failed to move $veth_ns_c to $ns_name"; exit 1; }
    sudo ip link set "$veth_host_c" master "$client_bridge" || { log_error "Failed to attach $veth_host_c to bridge $client_bridge"; exit 1; }
    sudo ip link set "$veth_host_c" up || { log_error "Failed to bring up $veth_host_c"; exit 1; }
    sudo ip netns exec "$ns_name" ip link set dev "$veth_ns_c" up
    read -r -a client_ips_array <<< "$client_ips_array_str"
    for full_ip_cidr in "${client_ips_array[@]}"; do
        if [[ "$full_ip_cidr" == *":"* ]]; then # IPv6
            local ip_only
            ip_only=$(echo "$full_ip_cidr" | cut -d'/' -f1)
            sudo ip netns exec "$ns_name" bash -c "ip -6 addr add '${ip_only}/128' dev '${veth_ns_c}'" || { log_error "Failed to add IPv6 address ${ip_only}/128 to $veth_ns_c in $ns_name"; exit 1; }
            sudo ip netns exec "$ns_name" bash -c "ip -6 route add '${full_ip_cidr}' dev '${veth_ns_c}'" || { log_error "Failed to add IPv6 route $full_ip_cidr via $veth_ns_c in $ns_name"; exit 1; }
        else # IPv4
            sudo ip netns exec "$ns_name" ip addr add "$full_ip_cidr" dev "$veth_ns_c" || { log_error "Failed to add IPv4 $full_ip_cidr to $veth_ns_c in $ns_name"; exit 1; }
        fi
    done
    log_info "Python Relay NS $ns_name: client interface $veth_ns_c configured."

    # Server-facing interface
    log_info "Configuring server-facing interface $veth_ns_s for $ns_name on $server_bridge..."
    sudo ip link add name "$veth_host_s" type veth peer name "$veth_ns_s" || { log_error "Failed to create server-facing veth for $ns_name"; exit 1; }
    sudo ip link set "$veth_ns_s" netns "$ns_name" || { log_error "Failed to move $veth_ns_s to $ns_name"; exit 1; }
    sudo ip link set "$veth_host_s" master "$server_bridge" || { log_error "Failed to attach $veth_host_s to bridge $server_bridge"; exit 1; }
    sudo ip link set "$veth_host_s" up || { log_error "Failed to bring up $veth_host_s"; exit 1; }
    sudo ip netns exec "$ns_name" ip link set dev "$veth_ns_s" up
    read -r -a server_ips_array <<< "$server_ips_array_str"
    for full_ip_cidr in "${server_ips_array[@]}"; do
         if [[ "$full_ip_cidr" == *":"* ]]; then # IPv6
            local ip_only
            ip_only=$(echo "$full_ip_cidr" | cut -d'/' -f1)
            sudo ip netns exec "$ns_name" bash -c "ip -6 addr add '${ip_only}/128' dev '${veth_ns_s}'" || { log_error "Failed to add IPv6 address ${ip_only}/128 to $veth_ns_s in $ns_name"; exit 1; }
            sudo ip netns exec "$ns_name" bash -c "ip -6 route add '${full_ip_cidr}' dev '${veth_ns_s}'" || { log_error "Failed to add IPv6 route $full_ip_cidr via $veth_ns_s in $ns_name"; exit 1; }
        else # IPv4
            sudo ip netns exec "$ns_name" ip addr add "$full_ip_cidr" dev "$veth_ns_s" || { log_error "Failed to add IPv4 $full_ip_cidr to $veth_ns_s in $ns_name"; exit 1; }
        fi
    done
    log_info "Python Relay NS $ns_name: server interface $veth_ns_s configured."

    sudo ip netns exec "$ns_name" ip link set dev lo up
    log_info "Enabling IP forwarding in $ns_name..."
    sudo ip netns exec "$ns_name" sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sudo ip netns exec "$ns_name" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
    log_info "Namespace $ns_name fully configured for Python relay."
}

create_kea_config_dirs() {
    log_info "Creating runtime directories..."
    sudo mkdir -p "$RED_NS_RUNTIME_DIR" "$BLUE_NS_RUNTIME_DIR" "$PYRELAY_NS_RUNTIME_DIR"
    sudo chmod -R 777 "${KEA_RUNTIME_BASE_DIR}"
    log_info "Runtime directories created under $KEA_RUNTIME_BASE_DIR"
}

# --- Kea Config Generation ---
generate_kea_dhcp4_config() {
    local ns_name="$1"
    local conf_file_path="$2"
    local lease_file_path="$3"
    local interface_name="$4"
    local subnet1_cidr="$5"
    local pool1_range="$6"
    local subnet2_cidr="$7"
    local pool2_range="$8"
    local control_socket_path="$9"

    log_info "Generating Kea DHCPv4 config for $ns_name at $conf_file_path..."

    # Specific classification for ns_red
    local client_classes_config=""
    local subnet1_class_filter=""
    local subnet2_class_filter=""

    if [ "$ns_name" == "ns_red" ]; then
        client_classes_config=$(cat << EOCC
        "client-classes": [
            {
                "name": "VIDEO_USERS_CLASS",
                "test": "relay4.circuit-id == 'VIDEO_CIRCUIT'"
            },
            {
                "name": "DATA_USERS_CLASS",
                "test": "relay4.circuit-id == 'DATA_CIRCUIT'"
            }
        ],
EOCC
)
        subnet1_class_filter='"client-class": "VIDEO_USERS_CLASS",'
        subnet2_class_filter='"client-class": "DATA_USERS_CLASS",'
    fi

    cat << EOF > "$conf_file_path"
{
    "Dhcp4": {
        ${client_classes_config}
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
                "name": "shared_net_v4_for_${ns_name}",
                "interface": "$interface_name",
                "subnet4": [
                    {
                        ${subnet1_class_filter}
                        "subnet": "$subnet1_cidr",
                        "pools": [ { "pool": "$pool1_range" } ],
                        "option-data": [ { "name": "routers", "data": "${subnet1_cidr%.*}.1" } ]
                    },
                    {
                        ${subnet2_class_filter}
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
    local subnet1_prefix="$5"
    local pool1_range="$6"
    local subnet2_prefix="$7"
    local pool2_range="$8"
    local control_socket_path="$9"

    log_info "Generating Kea DHCPv6 config for $ns_name at $conf_file_path..."

    local client_classes_config_v6=""
    local subnet1_class_filter_v6=""
    local subnet2_class_filter_v6=""

    if [ "$ns_name" == "ns_red" ]; then
        client_classes_config_v6=$(cat << EOCC
        "client-classes": [
            {
                "name": "V6_VIDEO_USERS_CLASS",
                "test": "relay6.interface-id == 'V6_VIDEO_LINK'"
            },
            {
                "name": "V6_DATA_USERS_CLASS",
                "test": "relay6.interface-id == 'V6_DATA_LINK'"
            }
        ],
EOCC
)
        subnet1_class_filter_v6='"client-class": "V6_VIDEO_USERS_CLASS",'
        subnet2_class_filter_v6='"client-class": "V6_DATA_USERS_CLASS",'
    fi

    cat << EOF > "$conf_file_path"
{
    "Dhcp6": {
        ${client_classes_config_v6}
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
            "name": "kea-dhcp6",
            "output_options": [{"output": "stdout"}],
            "severity": "INFO",
            "debuglevel": 0
        }],
        "shared-networks": [
            {
                "name": "shared_net_v6_for_${ns_name}",
                "interface": "$interface_name",
                "subnet6": [
                    {
                        ${subnet1_class_filter_v6}
                        "subnet": "$subnet1_prefix",
                        "pools": [ { "pool": "$pool1_range" } ]
                    },
                    {
                        ${subnet2_class_filter_v6}
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

# --- Python Relay Management (Placeholders) ---
start_python_relay() {
    local ns_name="ns_pyrelay"
    local client_if="v_pyrelay_c_ns"
    local server_if="v_pyrelay_s_ns"

    local ns_name="ns_pyrelay"
    local client_if="v_pyrelay_c_ns"
    local server_if="v_pyrelay_s_ns"

    # RED Server Details
    local red_server_v4_ip="192.168.10.1"
    local red_giaddr="192.168.10.254"
    local red_server_v6_ip="fd00:red::1"
    local red_link_address_v6="fd00:red::fe"

    # BLUE Server Details
    local blue_server_v4_ip="192.168.20.1"
    local blue_giaddr="192.168.20.254"
    local blue_server_v6_ip="fd00:blue::1"
    local blue_link_address_v6="fd00:blue::fe"

    local pid_file="${PYRELAY_NS_RUNTIME_DIR}/pyrelay.pid"
    local log_file="${PYRELAY_NS_RUNTIME_DIR}/pyrelay.log"

    log_info "Attempting to start Python DHCP Relay in namespace $ns_name..."

    if [ ! -f "$PYTHON_RELAY_SCRIPT_PATH" ]; then
        log_error "Python relay script $PYTHON_RELAY_SCRIPT_PATH not found. Cannot start relay."
        log_info "Please create $PYTHON_RELAY_SCRIPT_PATH first with the relay logic."
        echo "dummy_relay_pid_not_started" > "$pid_file" # Dummy for status
        return 1
    fi

    local relay_args=(
        --client-iface "$client_if"
        --server-iface "$server_if"
        --red-server-v4 "$red_server_v4_ip"
        --red-giaddr "$red_giaddr"
        --red-server-v6 "$red_server_v6_ip"
        --red-link-address-v6 "$red_link_address_v6"
        --blue-server-v4 "$blue_server_v4_ip"
        --blue-giaddr "$blue_giaddr"
        --blue-server-v6 "$blue_server_v6_ip"
        --blue-link-address-v6 "$blue_link_address_v6"
        --pid-file "$pid_file"
        --log-file "$log_file"
        # Add --log-level or -f for foreground from script args if needed
    )

    log_info "Executing: sudo ip netns exec $ns_name python3 $PYTHON_RELAY_SCRIPT_PATH ${relay_args[*]} &"

    sudo ip netns exec "$ns_name" python3 "$PYTHON_RELAY_SCRIPT_PATH" "${relay_args[@]}" > "$log_file" 2>&1 &

    # We are backgrounding the `ip netns exec python3 ...` command.
    # The Python script itself should handle creating its own PID file specified by --pid-file.
    # For now, we save the PID of 'ip netns exec'. This is not ideal for daemon management.
    # The Python script should ideally daemonize and manage its own PID.
    local exec_pid=$!
    echo "$exec_pid" > "${PYRELAY_NS_RUNTIME_DIR}/pyrelay_exec.pid" # PID of ip netns exec

    sleep 2 # Give it a moment to start / write its own PID file

    if [ -f "$pid_file" ] && ps -p "$(cat "$pid_file")" > /dev/null; then
        log_info "Python DHCP Relay started in $ns_name. True PID: $(cat "$pid_file"), Log: $log_file"
    elif ps -p "$exec_pid" > /dev/null; then
        log_warn "Python DHCP Relay exec process (PID $exec_pid) is running, but true PID file $pid_file not found or process not matching. Python script might not have started correctly or not managing PID file."
        log_info "Further relay status check will rely on exec_pid $exec_pid."
    else
        log_error "Python DHCP Relay in $ns_name FAILED to start. Check log: $log_file"
        cat "$log_file"
        return 1
    fi
}

stop_python_relay() {
    local true_pid_file="${PYRELAY_NS_RUNTIME_DIR}/pyrelay.pid"
    local exec_pid_file="${PYRELAY_NS_RUNTIME_DIR}/pyrelay_exec.pid"
    local pid_to_kill=""

    log_info "Attempting to stop Python DHCP Relay..."

    if [ -f "$true_pid_file" ]; then
        pid_to_kill=$(cat "$true_pid_file")
        log_info "Found true PID file for Python relay: $true_pid_file with PID $pid_to_kill."
    elif [ -f "$exec_pid_file" ]; then
        pid_to_kill=$(cat "$exec_pid_file")
        log_warn "True PID file not found. Using exec PID file: $exec_pid_file with PID $pid_to_kill."
    fi

    if [ -n "$pid_to_kill" ]; then
        if ps -p "$pid_to_kill" > /dev/null; then
            log_info "Stopping Python DHCP Relay (PID $pid_to_kill)..."
            # Try TERM first, then KILL. Python script should handle SIGTERM.
            sudo kill -TERM "$pid_to_kill"
            sleep 1
            if ps -p "$pid_to_kill" > /dev/null; then
                log_info "Python Relay (PID $pid_to_kill) still running, sending SIGKILL..."
                sudo kill -KILL "$pid_to_kill"
            fi
            log_info "Python DHCP Relay (PID $pid_to_kill) stop signal sent."
        else
            log_info "Python DHCP Relay (PID $pid_to_kill) not running or PID file stale."
        fi
        sudo rm -f "$true_pid_file" "$exec_pid_file"
    else
        log_info "No PID file found for Python DHCP Relay. Maybe not started or already stopped."
    fi
}


# --- Kea Server Management ---
start_kea_server() {
    local ns_name="$1"
    local protocol="$2"
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
    local log_file="${KEA_RUNTIME_BASE_DIR}/${ns_name}/kea-${protocol}-server.log"
    sudo mkdir -p "$(dirname "$log_file")" # Ensure log directory exists

    sudo ip netns exec "$ns_name" "$kea_bin" -c "$conf_file_path" > "$log_file" 2>&1 &
    echo $! > "$pid_file"

    sleep 2
    if ps -p "$(cat $pid_file)" > /dev/null; then
        log_info "Kea $protocol server in $ns_name started (process group PID $(cat $pid_file)). Log: $log_file"
    else
        log_error "Kea $protocol server in $ns_name FAILED to start. Check log: $log_file"
        cat "$log_file"
        return 1
    fi
}

stop_kea_server() {
    local ns_name="$1"
    local protocol="$2"
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
            sudo kill -TERM "-$pgid"
            sleep 1
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
    fi
}

# --- Cleanup functions ---
cleanup_namespace_full() {
    local ns_name="$1"
    local veth_host_array_str="$2"

    log_info "Cleaning up namespace $ns_name..."
    if ip netns list | grep -q "^${ns_name}$"; then
        sudo ip netns del "$ns_name" || log_error "Failed to delete namespace $ns_name."
    else
        log_info "Namespace $ns_name does not exist."
    fi

    read -r -a veth_host_array <<< "$veth_host_array_str"
    for veth_host in "${veth_host_array[@]}"; do
        if ip link show "$veth_host" > /dev/null 2>&1; then
            log_info "Deleting veth $veth_host..."
            sudo ip link del "$veth_host" || log_error "Failed to delete veth $veth_host."
        fi
    done
}

cleanup_bridge() {
    local bridge_name="$1"
    if ip link show "$bridge_name" > /dev/null 2>&1; then
        log_info "Cleaning up bridge $bridge_name..."
        for iface in $(ip link show | grep "master $bridge_name" | awk '{print $2}' | sed 's/@.*//'); do
            if ip link show "$iface" > /dev/null 2>&1; then
                log_info "Detaching $iface from $bridge_name..."
                sudo ip link set dev "$iface" nomaster || log_warn "Failed to detach $iface from $bridge_name"
            fi
        done
        sudo ip link set dev "$bridge_name" down || log_error "Failed to bring down bridge $bridge_name."
        sudo ip link del dev "$bridge_name" || log_error "Failed to delete bridge $bridge_name."
    else
        log_info "Bridge $bridge_name does not exist."
    fi
}

cleanup_runtime_dirs() {
    log_info "Cleaning up runtime directories under $KEA_RUNTIME_BASE_DIR..."
    if [ -d "$KEA_RUNTIME_BASE_DIR" ]; then
        sudo rm -rf "$KEA_RUNTIME_BASE_DIR"
        log_info "Runtime directory $KEA_RUNTIME_BASE_DIR removed."
    else
        log_info "Runtime directory $KEA_RUNTIME_BASE_DIR does not exist."
    fi
}

# --- Main actions ---
action_start() {
    log_info "=== Starting Kea Server & Python Relay Environment Setup ==="
    check_root
    check_python_installation

    create_bridge_if_not_exists "$BRIDGE_NAME"
    create_bridge_if_not_exists "$BR_CLIENTS_NAME"
    create_kea_config_dirs

    # Setup Kea Server Namespaces
    setup_server_namespace "ns_red" "veth_red_host" "veth_red_ns" \
        "192.168.10.1/24" "192.168.11.1/24" \
        "fd00:red::1/64" "fd00:red:1::1/64" \
        "$BRIDGE_NAME"

    setup_server_namespace "ns_blue" "veth_blue_host" "veth_blue_ns" \
        "192.168.20.1/24" "192.168.21.1/24" \
        "fd00:blue::1/64" "fd00:blue:1::1/64" \
        "$BRIDGE_NAME"

    # Generate Kea Server Configs
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

    # Setup Python Relay Namespace
    setup_pyrelay_namespace

    start_python_relay # Start our Python relay

    log_info "All Kea servers and Python Relay network infrastructure started."
    log_info "Python relay process (placeholder) initiated."
    log_info "NEXT: Implement Python relay agent logic in $PYTHON_RELAY_SCRIPT_PATH."
    log_info "Then, to test, create a client namespace, connect it to $BR_CLIENTS_NAME, and run dhclient."
    log_info "Example client setup:"
    log_info " sudo ip netns add ns_client"
    log_info " sudo ip link add v_cli_h type veth peer name v_cli_ns"
    log_info " sudo ip link set v_cli_ns netns ns_client"
    log_info " sudo ip link set v_cli_h master $BR_CLIENTS_NAME"
    log_info " sudo ip link set v_cli_h up"
    log_info " sudo ip netns exec ns_client ip link set dev lo up"
    log_info " sudo ip netns exec ns_client ip link set dev v_cli_ns up"
    log_info " sudo ip netns exec ns_client dhclient -4 -v v_cli_ns  # For DHCPv4"
    log_info " sudo ip netns exec ns_client dhclient -6 -v v_cli_ns  # For DHCPv6"
    log_info " (Cleanup client ns: sudo ip netns exec ns_client dhclient -r v_cli_ns; sudo ip netns del ns_client; sudo ip link del v_cli_h)"
}

action_stop() {
    log_info "=== Stopping Kea Servers & Python Relay ==="
    check_root
    stop_python_relay
    stop_kea_server "ns_red" "dhcp4"
    stop_kea_server "ns_red" "dhcp6"
    stop_kea_server "ns_blue" "dhcp4"
    stop_kea_server "ns_blue" "dhcp6"
    log_info "All Kea servers and Python relay stopped."
}

action_cleanup() {
    log_info "=== Cleaning Up Environment ==="
    check_root
    action_stop

    cleanup_namespace_full "ns_pyrelay" "v_pyrelay_c_h v_pyrelay_s_h"
    cleanup_namespace_full "ns_red" "veth_red_host"
    cleanup_namespace_full "ns_blue" "veth_blue_host"

    cleanup_bridge "$BR_CLIENTS_NAME"
    cleanup_bridge "$BRIDGE_NAME"

    cleanup_runtime_dirs
    log_info "Cleanup complete."
}

action_status() {
    log_info "=== Kea Server & Python Relay Status ==="
    check_root
    for ns in ns_red ns_blue ns_pyrelay; do
        for proto in dhcp4 dhcp6; do
            local pid_file=""
            if [[ "$ns" == "ns_pyrelay" ]]; then
                pid_file="${PYRELAY_NS_RUNTIME_DIR}/pyrelay.pid"
                if [ "$proto" == "dhcp6" ]; then continue; fi # Check relay PID only once

                if [ ! -f "$PYTHON_RELAY_SCRIPT_PATH" ]; then
                    log_info "Python relay script $PYTHON_RELAY_SCRIPT_PATH not found. Status check N/A."
                    break # Break inner loop for this ns
                fi
            else
                pid_file="${KEA_RUNTIME_BASE_DIR}/${ns}/kea-${proto}.pid"
            fi

            local process_name="Kea $proto server"
            if [[ "$ns" == "ns_pyrelay" ]]; then process_name="Python Relay"; fi

            if [ -f "$pid_file" ]; then
                pgid=$(cat "$pid_file")
                # Check if the pgid is a number and if the process/group exists
                if [[ "$pgid" =~ ^[0-9]+$ ]] && ps -p "$pgid" > /dev/null; then
                    log_info "$process_name in $ns is RUNNING (PID/PGID $pgid)."
                elif [[ "$pgid" == "dummy_relay_pid_not_started" ]]; then
                     log_info "$process_name in $ns is NOT STARTED (script not found)."
                else
                    log_info "$process_name in $ns is STOPPED (stale PID file $pid_file)."
                fi
            else
                log_info "$process_name in $ns is STOPPED (no PID file)."
            fi
        done
    done
}


# --- Main script logic ---

PYRELAY_LOG_LEVEL="info" # Default log level for python relay

# Parse command-line options for kea_server_setup.sh itself
while getopts ":l:" opt; do
  case ${opt} in
    l )
      PYRELAY_LOG_LEVEL=$OPTARG
      ;;
    \? )
      echo "Invalid Option: -$OPTARG" 1>&2
      echo "Usage: $0 [-l <pyrelay_log_level>] <start|stop|restart|status|cleanup>"
      exit 1
      ;;
    : )
      echo "Invalid Option: -$OPTARG requires an argument" 1>&2
      echo "Usage: $0 [-l <pyrelay_log_level>] <start|stop|restart|status|cleanup>"
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))


if [ -z "$1" ]; then
    echo "Usage: $0 [-l <pyrelay_log_level>] <start|stop|restart|status|cleanup>"
    echo "  <pyrelay_log_level>: debug, info, warning, error, critical (default: info)"
    exit 1
fi

ACTION=$1

# Pass PYRELAY_LOG_LEVEL to start_python_relay, it will then pass it to the python script.
# This requires start_python_relay to accept it as an argument. Let's assume it does for now.

case "$ACTION" in
    start)
        action_start "$PYRELAY_LOG_LEVEL" # Pass it to action_start
        ;;
    stop)
        action_stop
        ;;
    restart)
        action_stop
        sleep 2
        action_start "$PYRELAY_LOG_LEVEL" # Pass it to action_start
        ;;
    status)
        action_status
        ;;
    cleanup)
        action_cleanup
        ;;
    *)
        echo "Invalid action: $ACTION"
        echo "Usage: $0 [-l <pyrelay_log_level>] <start|stop|restart|status|cleanup>"
        exit 1
        ;;
esac

exit 0
