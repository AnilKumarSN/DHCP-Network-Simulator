### `README.md`

# DHCP Network Simulator

This project is a high-performance, C-based tool for creating complex virtual network topologies to test and validate production-grade DHCP servers like ISC Kea. It moves beyond simple shell scripts by using programmatic, low-level Linux networking APIs to simulate hundreds of concurrent DHCP clients across multiple, isolated network namespaces.

The primary goal of this simulator is to test a DHCP server's ability to perform **client classification** in a **multi-subnet, shared-link environment**. It programmatically creates two isolated networks (`red` and `blue`), starts dedicated Kea servers within them, and then simulates unique DHCP clients to verify that they receive IP addresses from the correct, pre-defined pools based on their Vendor Class Identifier (VCI).

---

## Key Features

-   **Robust Programmatic Networking:** Uses a sequence of validated `iproute2` commands driven by C to reliably create and tear down network namespaces and `veth` pairs.
-   **Concurrent Client Simulation:** Implements a high-performance, `epoll`-based event loop to simulate a large number of DHCPv4 and DHCPv6 clients concurrently without the overhead of multi-threading.
-   **Link-Layer Packet Crafting:** Builds DHCPv4 packets from the ground up using `AF_PACKET` raw sockets and a **BPF filter**, providing total control over the Ethernet frame and preventing kernel interference.
-   **Correct DHCPv6 UDP Sockets:** Correctly uses `AF_INET6` UDP datagram sockets for DHCPv6, which is required to properly handle unicast replies from the server and avoid `ICMP Port Unreachable` errors.
-   **Advanced DHCP Testing:** The Kea configurations are specifically designed to test `shared-networks`, allowing a single server interface to serve clients for multiple IP subnets based on their VCI.
-   **Integrated Packet Capture:** Automatically runs `tcpdump` on the virtual interfaces during the simulation and saves the results to `.pcap` files for deep analysis with tools like Wireshark or `tshark`.
-   **Scalability-Ready:** The code includes client-side throttling (staggered start) and the build script tunes kernel parameters to handle a high volume of simultaneous lease requests, making it suitable for stress testing.

---

## Architecture Deep Dive

The simulator creates a virtual network topology that isolates two distinct test environments, `red` and `blue`, from each other and from the host machine's primary network.

### Network Topology

The following diagram illustrates the architecture created by the simulator:

```
+-------------------------------------------------------------+
|                     Host Machine (Root Namespace)           |
|                                                             |
|   +--------------------------+                              |
|   |   ./netns_sim (Client    |                              |
|   |      Simulator &         |                              |
|   |      Orchestrator)       |                              |
|   +--------------------------+                              |
|      |                |                                     |
|      | (veth-r-red)   | (veth-r-blue)                       |
+------|----------------|-------------------------------------+
       |                |
 (Virtual Cable)       (Virtual Cable)
       |                |
+------|----------------|-------------------------------------+
|      | (veth-ns-red)  | (veth-ns-blue)                      |
|      |                |                                     |
| +------------------+  |  +------------------+               |
| | Kea DHCPv4 & v6  |  |  | Kea DHCPv4 & v6  |               |
| | Server Processes |  |  | Server Processes |               |
| +------------------+  |  +------------------+               |
|      (Listens on      |      (Listens on                    |
|      veth-ns-red)     |      veth-ns-blue)                  |
|                       |                                     |
|  RED Namespace        |  BLUE Namespace                     |
+-----------------------+-------------------------------------+
```

### Component Breakdown

-   **`build.sh` (The Entry Point):** A robust shell script that prepares the host system, performs a clean build, and executes the final binary with the correct permissions. It handles:
    1.  Forceful cleanup of any leftover resources from previous runs.
    2.  Tuning kernel neighbor table parameters (`sysctl`) to handle high client counts.
    3.  Running `cmake` and `make`.
    4.  Executing the final `netns_sim` binary with `sudo`.

-   **`main.c` (The Orchestrator):** The main C program that controls the entire simulation lifecycle from start to finish. It is responsible for calling the other modules in the correct, deterministic sequence.

-   **`netns_manager.c` (The Plumber):** A toolkit responsible for all network setup and teardown. It exclusively uses `system()` calls to the `iproute2` (`ip`) and `sysctl` command-line tools. This "hybrid" approach was chosen over pure `libnl` because it proved to be more reliable and portable, especially in virtualized environments like WSL2 where low-level netlink library calls can behave unexpectedly. It includes a critical `is_interface_ready` polling function to ensure network links are fully operational before use.

-   **`dhcp_crafter.h` (The Data Model):** This header defines the two most important data structures:
    -   `client_state_t`: An `enum` that defines the states of the DORA (v4) and SARR (v6) state machines.
    -   `simulated_client`: A `struct` that holds all state for a single simulated client, including its MAC address, VCI, transaction IDs, and leased IPs for both protocols.

-   **`dhcp_crafter_v4.c` (The DHCPv4 Client):**
    -   Uses `AF_PACKET` raw sockets to have complete control over the Ethernet frame.
    -   Crucially, it attaches a **BPF filter** to the socket. This filter instructs the kernel to deliver all IP/UDP packets for ports 67 and 68 directly to this socket, bypassing the kernel's normal IP stack. This prevents the kernel from generating `ICMP Port Unreachable` messages when it sees a DHCP Offer broadcast, which would otherwise disrupt the simulation.

-   **`dhcp_crafter_v6.c` (The DHCPv6 Client):**
    -   Uses `AF_INET6` standard UDP sockets (`SOCK_DGRAM`). This is the architecturally correct approach for DHCPv6.
    -   DHCPv6 servers often reply with a **unicast** `ADVERTISE` packet. A raw `AF_PACKET` socket is not designed to reliably receive unicast IP traffic destined for its own MAC address without complex filtering. A UDP socket, when bound to the DHCPv6 client port (`546`), allows the kernel to handle all Neighbor Discovery and routing, ensuring the unicast replies are delivered correctly to our application. This solves the "Port Unreachable" problem seen in the `tshark` captures.

---

## Code Flow (Execution Walkthrough)

The `main` function executes the following sequence:

1.  **Initial Cleanup:** `cleanup_all_environments()` is called to remove any namespaces or `veth` pairs left over from a previous or crashed run.
2.  **Environment Setup:** `setup_all_environments()` orchestrates the creation of the networks:
    1.  `setup_namespace_environment("red", ...)` is called. This function:
        -   Creates the `red` namespace and the `veth-r-red`/`veth-ns-red` pair.
        -   Moves `veth-ns-red` into the namespace.
        -   Disables IPv6 Duplicate Address Detection (DAD) on the interface for stability.
        -   Assigns two IPv4 and two IPv6 addresses to `veth-ns-red`, making it a multi-homed interface.
        -   Brings both `veth-ns-red` (inside the namespace) and `veth-r-red` (in the root) to the `UP` state.
        -   Polls the interface state until it is confirmed to be fully operational.
    2.  The same process is repeated for the `blue` namespace.
3.  **Start Kea Servers:** Four Kea processes (v4 and v6 for both red and blue) are started in the background inside their respective namespaces using `run_command_in_ns()`. A `sleep()` gives them time to initialize.
4.  **Start Packet Captures:** `start_packet_captures()` forks two `tcpdump` processes in the background, one for each root `veth` interface, saving the traffic to `.pcap` files.
5.  **Run Simulations:** `run_all_simulations()` is called.
    -   It initializes the client data structures for the `red` namespace.
    -   It calls `perform_concurrent_dhcpv4()` and `perform_concurrent_dhcpv6()`, which contain the main `epoll` event loops that drive the client state machines.
    -   It repeats the process for the `blue` namespace.
6.  **Stop Packet Captures:** `stop_packet_captures()` reads the saved PIDs of the `tcpdump` processes and sends them a `SIGINT` to terminate them gracefully, ensuring all captured packets are flushed to disk.
7.  **Pause for Inspection:** The program calls `getchar()` to pause, allowing the user to examine the logs and `.pcap` files before the environment is destroyed.
8.  **Final Cleanup:** After the user presses Enter, `cleanup_all_environments()` is called again to return the system to its original state.

---

## Kea IP Address & Lease Logic

This simulator is specifically designed to test a powerful Kea feature for handling multiple subnets on a single physical network segment.

#### General Kea Principles

-   **Client Classification:** Kea can inspect any part of an incoming DHCP packet to assign the client to a "class". In our case, we use the **Vendor Class Identifier (VCI, Option 60 for v4; Option 16 for v6)**. Our C code crafts packets with unique VCI strings like `"red-client-class-1"`. The Kea config has `client-classes` definitions with `test` expressions to match these strings.
-   **Pools and Subnets:** A `subnet` block defines a logical IP network (e.g., `10.10.10.0/24`). A `pool` within that subnet defines a range of addresses that can be leased to clients (e.g., `10.10.10.100 - 10.10.149`).
-   **Shared Networks:** This is the key concept being tested. A `shared-networks` block tells Kea that all the `subnet` blocks defined inside it are accessible on the *same physical link*. This is essential for our setup where the `veth-ns-red` interface has IP addresses in two different subnets.

#### How Kea Assigns an IP in This Simulation

Let's trace the logic for **Client 2** in the `red` namespace, which has the VCI `"red-client-class-2"`.

1.  **Packet Arrival:** The `DISCOVER` packet arrives on `veth-ns-red`.
2.  **Shared Network Identification:** Kea sees the interface is part of the `red-shared-network`. It now knows that it can consider *any* subnet within this shared block for the client.
3.  **Classification:** Kea inspects Option 60, finds `"red-client-class-2"`, and successfully classifies the client into the `RED_CLIENT_TYPE_2` class.
4.  **Subnet Selection:** Kea iterates through the subnets inside the shared network:
    -   **Subnet 1 (`10.10.10.0/24`):** It checks the subnet's restriction: `client-classes: ["RED_CLIENT_TYPE_1"]`. The client's class (`RED_CLIENT_TYPE_2`) does not match. Kea discards this subnet as a possibility.
    -   **Subnet 2 (`10.10.11.0/24`):** It checks the subnet's restriction: `client-classes: ["RED_CLIENT_TYPE_2"]`. **This is a match!**
5.  **Lease Offer:** Because a matching subnet was found, Kea allocates an available IP from that subnet's pool (e.g., `10.10.11.100`) and sends the `DHCPOFFER`.

This demonstrates that the combination of `shared-networks` and `client-classes` allows a single Kea server to correctly route clients to different logical subnets based on their identity, even when they all exist on the same physical link.

---

## Prerequisites & How to Run

You must be on a Debian-based system (e.g., Ubuntu 22.04+) or a bare-metal Linux server.

1.  **Install Dependencies:**
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential cmake pkg-config iproute2 tcpdump \
                         libnl-3-dev libnl-route-3-dev \
                         kea-dhcp4-server kea-dhcp6-server
    ```

2.  **Build and Run:**
    Use the provided shell script. It handles cleanup, kernel tuning, building, and executing the simulator with the required permissions.
    ```bash
    chmod +x build.sh
    ./build.sh
    ```

3.  **Analyze Results:**
    -   Follow the console output for the live status of the simulation.
    -   After the simulation completes, inspect the generated packet capture files in the `build/` directory using Wireshark or `tshark`:
        ```bash
        tshark -r build/red_capture.pcap
        tshark -r build/blue_capture.pcap
        ```
