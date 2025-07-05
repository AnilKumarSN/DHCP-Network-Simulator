# Dual Stack DHCP Client Simulator

This script simulates multiple dual-stack (DHCPv4 and DHCPv6) clients, each operating within its own network namespace. It uses ISC Kea's `perfdhcp` tool to generate DHCP traffic. This is useful for testing DHCP server performance and functionality at scale.

## Features

*   Simulates a configurable number of DHCP clients.
*   Each client operates in an isolated network namespace.
*   Supports both DHCPv4 and DHCPv6 traffic generation via `perfdhcp`.
*   Customizable rate, duration, and packet templates for `perfdhcp`.
*   Logs output from each `perfdhcp` instance to separate files.
*   Automatic setup and cleanup of network namespaces and virtual Ethernet (veth) interfaces.

## Prerequisites

1.  **Linux System**: Required for network namespace and `iproute2` functionalities.
2.  **Python 3**: The simulator script is written in Python 3.
3.  **`iproute2`**: The `ip` command is used extensively for network configuration. Install it if not present (e.g., `sudo apt install iproute2`).
4.  **ISC Kea `perfdhcp`**: The `perfdhcp` executable must be installed and accessible.
    *   The provided `setup_kea.sh` script can be used to install Kea 3.0.0, including `perfdhcp` (typically installed to `/usr/sbin/perfdhcp`). Ensure this script is run first if Kea is not already installed.
5.  **Root Privileges**: The script `dhcp_simulator.py` must be run as root (or with `sudo`) because it creates network namespaces and manipulates network interfaces.
6.  **Target DHCP Server(s)**: You need one or more DHCP servers (v4 and/or v6) configured and reachable on the network segment where the simulated clients will appear.

## Setup

### 1. Install Kea and `perfdhcp`

If you don't have Kea 3.0.0 and `perfdhcp` installed, use the `setup_kea.sh` script:

```bash
chmod +x setup_kea.sh
sudo ./setup_kea.sh
```
This will install the necessary Kea components, including `perfdhcp` (usually at `/usr/sbin/perfdhcp`).

### 2. Prepare Host Network

The simulated clients connect to the host network via virtual Ethernet (veth) pairs. The host-facing end of these veth pairs needs to be connected to the network segment where your DHCP server(s) reside.

A common way to achieve this is to use a **Linux bridge**:

1.  **Create a bridge** (e.g., `br0`):
    ```bash
    sudo ip link add name br0 type bridge
    sudo ip link set dev br0 up
    ```

2.  **Connect a physical interface to the bridge** (optional, if you want the bridge to connect to an external network):
    Ensure your physical interface (e.g., `eth1`) is not configured with an IP address directly.
    ```bash
    # Example: removing IP from eth1 and adding it to br0
    # sudo ip addr flush dev eth1
    # sudo ip link set dev eth1 master br0
    # sudo ip addr add <your_network_ip_for_bridge>/<prefix> dev br0
    ```
    Alternatively, if the DHCP server is running on the same host, the bridge might not need an external physical interface, but it will still need an IP in the server's subnet if the server is configured to listen on that bridge IP.

    When running `dhcp_simulator.py`, you will specify this bridge interface using the `--host-iface br0` argument. The script will then automatically connect the host-side veth pairs of the simulated clients to this bridge.

### 3. Configure Target DHCP Server(s)

Ensure your DHCPv4 and/or DHCPv6 servers are configured to serve leases on the network segment connected to `--host-iface`.

*   **Example Kea DHCPv4 Configuration Snippet (`kea-dhcp4.conf`)**:
    ```json
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": [ "br0" ] // Or the interface Kea should listen on
        },
        "lease-database": {
            "type": "memfile",
            "lfc-interval": 3600
        },
        "subnet4": [
            {
                "subnet": "192.168.100.0/24",
                "pools": [ { "pool": "192.168.100.10 - 192.168.100.200" } ],
                "option-data": [
                    { "name": "routers", "data": "192.168.100.1" }
                ]
            }
        ]
    }
    ```
*   Start your Kea server(s) (e.g., `sudo systemctl start isc-kea-dhcp4-server`).

## Usage

Run the simulator script with `sudo`:

```bash
sudo python3 dhcp_simulator.py --num-clients <N> --host-iface <interface_name> [options]
```

### Command-Line Arguments

*   `--num-clients N`: (int, **required**) Number of dual-stack clients to simulate.
*   `--host-iface IFACE`: (str, **required**) Host-side network interface or bridge (e.g., `br0`) to connect clients to.
*   `--dhcpv4-server IP`: (str, optional) IP address of the DHCPv4 server. Skips v4 simulation if not provided.
*   `--dhcpv6-server IP_OR_ALIAS`: (str, optional) IP address of the DHCPv6 server, or 'all'/'servers' for multicast. Skips v6 simulation if not provided.
*   `--rate R`: (int, default: 10) Target requests per second per client (for each protocol).
*   `--duration T`: (int, default: 60) Duration of the test in seconds for each client.
*   `--v4-template FILE`: (str, optional) Path to a custom DHCPv4 packet template file for `perfdhcp`.
*   `--v6-template FILE`: (str, optional) Path to a custom DHCPv6 packet template file for `perfdhcp`.
*   `--perfdhcp-path PATH`: (str, default: `/usr/sbin/perfdhcp`) Path to the `perfdhcp` executable.
*   `--output-dir DIR`: (str, default: `perfdhcp_results`) Directory to store `perfdhcp` output logs.
*   `--base-mac AA:BB:CC:DD:EE:00`: (str, optional) Base MAC for DHCPv4 clients. The script increments the last octet for each client.
*   `--base-duid DUID_HEX`: (str, optional) Base DUID (hex string) for DHCPv6 clients. The script attempts to increment the last byte for uniqueness.

### Example

Simulate 5 dual-stack clients connecting via `br0`, targeting a local DHCPv4 server at `192.168.100.1` and any DHCPv6 server via multicast, for 30 seconds:

```bash
sudo python3 dhcp_simulator.py \
    --num-clients 5 \
    --host-iface br0 \
    --dhcpv4-server 192.168.100.1 \
    --dhcpv6-server all \
    --duration 30 \
    --output-dir ./client_logs
```

## Output and Logs

*   The script will print status messages to the console during setup, execution, and cleanup.
*   A summary of successful/failed simulations for DHCPv4 and DHCPv6 will be printed at the end.
*   Detailed logs from each `perfdhcp` instance are stored in the directory specified by `--output-dir` (default: `perfdhcp_results`).
    *   Log files are named `client_<id>_v4.log` and `client_<id>_v6.log`.
    *   These logs contain the raw output of `perfdhcp`, including statistics on packets sent/received, lease times, etc.

## Troubleshooting

*   **Permissions**: Ensure the script is run with `sudo`.
*   **`perfdhcp` not found**: Verify `perfdhcp` is installed and `--perfdhcp-path` is correct.
*   **No DHCP Offers/Advertisements**:
    *   Check if your DHCP server is running and configured for the correct subnet.
    *   Verify the `--host-iface` (e.g., bridge `br0`) is correctly set up and can reach the DHCP server.
    *   Check firewall rules on the host or DHCP server machine.
    *   Inspect `tcpdump` or Wireshark on the `--host-iface` or on the DHCP server's interface to see if DHCP packets are flowing as expected.
*   **Namespace/veth errors**: Errors from `ip netns` or `ip link` commands usually indicate issues with setup or cleanup. The script attempts to clean up resources, but manual cleanup might occasionally be needed if the script exits prematurely:
    *   List namespaces: `sudo ip netns list`
    *   Delete a namespace: `sudo ip netns del <namespace_name>`
    *   List links: `ip link show`
    *   Delete a veth interface: `sudo ip link del <veth_host_name>`

## Running with Docker

This simulator can also be run inside a Docker container. This requires building a Docker image that includes all dependencies and the simulator scripts.

### 1. Build the Docker Image

A `Dockerfile` is provided. To build the image, navigate to the directory containing the `Dockerfile`, `setup_kea.sh`, and `dhcp_simulator.py`, then run:

```bash
docker build -t dhcp-simulator .
```
This command builds an image named `dhcp-simulator`. The build process includes running `setup_kea.sh` to install Kea and `perfdhcp` inside the image.

### 2. Run the Docker Container

Running the simulator inside Docker requires giving the container special privileges to manage network namespaces and interfaces. The `--network=host` option is also recommended to allow the simulator to interact with host network interfaces (like a host bridge) as intended by the script's design.

**Example `docker run` command:**

```bash
docker run --rm -it \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    --network=host \
    -v $(pwd)/my_client_logs:/app/perfdhcp_results \
    dhcp-simulator \
    --num-clients 2 \
    --host-iface br0 \
    --dhcpv4-server 192.168.100.1 \
    --output-dir /app/perfdhcp_results
    # Add other dhcp_simulator.py arguments as needed
```

**Explanation of `docker run` options:**

*   `--rm`: Automatically removes the container when it exits.
*   `-it`: Runs in interactive mode with a pseudo-TTY (useful for seeing output).
*   `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN`: Grants necessary capabilities to the container to manage network interfaces and namespaces. Alternatively, `--privileged` can be used for broader permissions, but it's less secure.
*   `--network=host`: The container shares the host's network stack. This allows `dhcp_simulator.py` (running inside the container) to directly see and manipulate host interfaces specified by `--host-iface` (e.g., a bridge `br0` on the host).
*   `-v $(pwd)/my_client_logs:/app/perfdhcp_results`: Mounts a directory from your host (`$(pwd)/my_client_logs`) into the container at `/app/perfdhcp_results`. The simulator script saves its logs to `/app/perfdhcp_results` (if `--output-dir` is set to that, which is the default if running from `/app`), so this makes the logs persistent on your host machine.
*   `dhcp-simulator`: The name of the Docker image built in the previous step.
*   The arguments after the image name (`--num-clients 2 ...`) are passed directly to the `dhcp_simulator.py` script.
    *   **Important**: If you use `-v` to mount an output directory, ensure the `--output-dir` argument passed to `dhcp_simulator.py` matches the *container-side path* of that volume mount (e.g., `/app/perfdhcp_results`).

### Considerations for Docker Networking

*   **`--network=host`**: This is the simplest way to allow the script to function as designed, by giving it access to the host's network interfaces. The `--host-iface` argument should then refer to an interface or bridge that exists on the Docker host (e.g., `br0` that you would have set up as per the "Prepare Host Network" section for non-Docker use).
*   **Alternative Docker Networks**: If you avoid `--network=host`, allowing the containerized script to manage veth pairs that connect to a *host-level* bridge or interface becomes significantly more complex. It would likely involve manually creating one side of a veth pair on the host and passing the other side into the container, then instructing the script to use that passed-in interface. This level of integration is not covered by the current script's automatic setup.
*   **Internal `sudo`**: The `dhcp_simulator.py` script uses `sudo` for `ip` commands. The Docker container runs as `root` by default, and the `Dockerfile` ensures `sudo` is available and passwordless for root, so these commands will execute correctly.
```
