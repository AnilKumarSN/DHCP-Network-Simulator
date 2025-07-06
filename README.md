# Advanced DHCP Environment with Python Relay Agent & Multi-VRF Kea Servers

## 1. Project Overview

This project provides a sophisticated testing and development environment for advanced DHCP scenarios. It features:

*   **Isolated Kea DHCP Servers**: Multiple ISC Kea DHCP server instances (both DHCPv4 and DHCPv6) run in separate Linux network namespaces (`ns_red`, `ns_blue`), simulating distinct VRFs (Virtual Routing and Forwarding instances) or isolated network segments, allowing for overlapping IP address spaces if needed and independent server configurations.
*   **Custom Python-Based DHCP Relay Agent (`dhcp_pyrelay.py`)**: A central component of this project is an in-house developed DHCP relay agent written in Python. This relay:
    *   Listens for client DHCP requests on a shared client network segment.
    *   Implements intelligent "bookkeeping" and policy logic to determine which VRF (i.e., which Kea server namespace - RED or BLUE) a client request should be forwarded to.
    *   Dynamically inserts or modifies DHCP options (e.g., Option 82 for DHCPv4, Interface-ID for DHCPv6) into client packets before relaying them. These options are used by Kea servers for fine-grained client classification and targeted subnet/pool selection.
    *   Handles the relaying of server replies back to the correct clients, stripping any options it had inserted.
*   **Orchestration Script (`kea_server_setup.sh`)**: A comprehensive Bash script automates the entire environment lifecycle:
    *   Creation of network namespaces for Kea servers and the Python relay.
    *   Setup of Linux bridges for client-side and server-side communication.
    *   Configuration and connection of virtual Ethernet (veth) pairs.
    *   Dynamic generation of Kea DHCP server configuration files.
    *   Launching Kea server processes.
    *   Launching the Python DHCP relay agent.
    *   Stopping all processes and cleaning up the network environment.
*   **Client Simulation (`dhcp_simulator.py` & `perfdhcp`)**: The existing `dhcp_simulator.py` (using Kea's `perfdhcp` tool) can be used to generate client traffic at scale to test the relay and server setup.

The primary goal is to create a flexible and controllable testbed for developing and validating advanced DHCP relaying policies, Kea server classification features, and interactions in a multi-VRF context.

## 2. Design Philosophy & Goals

*   **Isolation**: Simulate real-world network segmentation (VRFs) using network namespaces to ensure Kea server instances operate independently.
*   **Intelligent Relaying**: Move beyond basic relaying by implementing custom logic within the Python relay to make policy-based decisions for server selection and option manipulation.
*   **Targeted Allocation**: Enable precise control over which subnet/pool a client receives an IP address from, based on client characteristics and relay-defined policies.
*   **Kea Feature Validation**: Provide an environment to test and understand Kea's advanced features like `shared-networks`, client classification based on relay-inserted options (Option 82, Interface-ID, etc.).
*   **Extensibility**: Build a modular Python relay that can be extended with more complex policies and "bookkeeping" logic in the future.
*   **Automation**: Use `kea_server_setup.sh` to ensure repeatable and manageable setup/teardown of the complex environment.

## 3. Architecture & Network Design

```
+------------------------------------------------------------------------------------------------------+
| HOST MACHINE                                                                                         |
|                                                                                                      |
|  +----------------------------+      +----------------------------+      +--------------------------+
|  | Namespace: ns_red          |      | Namespace: ns_blue         |      | Namespace: ns_pyrelay    |
|  | (VRF RED Kea Servers)      |      | (VRF BLUE Kea Servers)     |      | (Python DHCP Relay Agent)|
|  |                            |      |                            |      |                          |
|  | +------------------------+ |      | +------------------------+ |      | +----------------------+ |
|  | | Kea DHCPv4 (red_cfg)   | |      | | Kea DHCPv4 (blue_cfg)  | |      | | dhcp_pyrelay.py      | |
|  | | Kea DHCPv6 (red_cfg)   | |      | | Kea DHCPv6 (blue_cfg)  | |      | | (Policy Engine &     | |
|  | +------------------------+ |      | +------------------------+ |      | |  Option Manipulation)  | |
|  |            |               |      |            |               |      | +----------------------+ |
|  |      veth_red_ns           |      |      veth_blue_ns          |      |      |           |       |
|  +------------|----------------+      +------------|----------------+      | v_pyrelay_c_ns | v_pyrelay_s_ns |
|               | (on br_dhcp_test)      (on br_dhcp_test)             (on br_clients)  (on br_dhcp_test)
|               |                               |                               |        |       |
|               +-------------------------------+-------------------------------+        |       |
|                                               |                                        |       |
|                    +----------------------------------------------------------+        |       |
|                    | Linux Bridge: br_dhcp_test (Server/Relay Backend Network)|<-------+       |
|                    +----------------------------------------------------------+                |
|                                                                                                |
|                    +----------------------------------------------------------+                |
|                    | Linux Bridge: br_clients (Shared Client Access Network)   |<---------------+
|                    +----------------------------------------------------------+
|                                                 |
|    +--------------------------+                 |
|    | Namespace: client_X      |<----------------+
|    | (dhclient / perfdhcp)    |
|    |      veth_clientX_ns     |
|    +--------------------------+
|           (Multiple such client namespaces)
|                                                                                                      |
+------------------------------------------------------------------------------------------------------+
```

**Key Architectural Decisions & Reasoning:**

*   **Network Namespaces for VRF Simulation**: Each Kea server set (RED and BLUE) runs in its own namespace. This provides strong isolation, allowing independent configurations, lease databases, and even overlapping IP subnets if the VRF scenario required it (though current example uses distinct subnets). The Python relay also runs in its own namespace (`ns_pyrelay`) to isolate its network interfaces and routing table.
*   **Linux Bridges for L2 Segmentation**:
    *   `br_dhcp_test`: Simulates a "backend" or "core" network segment where the Kea DHCP servers and the server-facing interface of the Python relay reside. This allows direct IP communication between the relay and the servers.
    *   `br_clients`: Simulates a shared "access" network or VLAN where all DHCP clients connect. The client-facing interface of the Python relay connects here to listen for client broadcasts/multicasts.
*   **Custom Python DHCP Relay Agent (`dhcp_pyrelay.py`)**:
    *   **Necessity**: Standard relay agents (like `isc-dhcp-relay`) are excellent for forwarding but typically offer limited built-in logic for dynamic server selection based on complex client attributes or for highly customized DHCP option insertion beyond basic Option 82 templating. This project requires the relay to be the "brains" for VRF mapping and policy-based option insertion.
    *   **Functionality**: It inspects client packets, applies a policy engine (initially MAC/DUID-based) to select a target VRF (RED/BLUE server), then further applies policy to determine what options (e.g., Option 82 Circuit ID, DHCPv6 Interface-ID) to insert to guide the chosen Kea server in its subnet/pool selection. It also handles stripping these options from server replies.
*   **Kea DHCP Servers**: Chosen for their modern design, extensive feature set, and powerful client classification capabilities which are essential for acting upon the information inserted by our Python relay. The `shared-networks` feature is critical for allowing a single Kea server interface to serve multiple logical subnets.
*   **Orchestration via Bash (`kea_server_setup.sh`)**: A shell script is sufficient and practical for orchestrating the setup, startup, and teardown of network elements and processes in this Linux-based environment.

## 4. Detailed Information Flow

### 4.1. DHCPv4 Client Request (e.g., DISCOVER)

1.  **Client Broadcast**: A DHCP client in `ns_client_X` (connected to `br_clients`) broadcasts a DHCPDISCOVER message.
2.  **Relay Reception**: `dhcp_pyrelay.py` (in `ns_pyrelay`), listening on `v_pyrelay_c_ns` (connected to `br_clients`), receives the broadcast.
3.  **Relay Policy - VRF Selection**: The Python relay inspects the client's MAC address (`chaddr`).
    *   Example: If MAC starts `00:aa:...`, it decides to target the RED VRF.
    *   Example: If MAC starts `00:bb:...`, it decides to target the BLUE VRF.
4.  **Relay Policy - Option 82 Info**: Based on further client MAC details (e.g., `00:aa:01:...` vs `00:aa:02:...`), the relay determines the value for Option 82 sub-options (e.g., Agent Circuit ID = "VIDEO_CIRCUIT" or "DATA_CIRCUIT").
5.  **Relay Packet Modification**:
    *   The relay sets the `giaddr` field in the DHCPDISCOVER packet. This `giaddr` is an IP address owned by the relay on its client-facing interface (`v_pyrelay_c_ns`) that falls within a subnet managed by the *chosen* Kea server (e.g., if RED VRF, `giaddr` might be `192.168.10.254`).
    *   The relay increments the `hops` count.
    *   The relay inserts the determined DHCP Option 82 with its sub-options.
6.  **Relay Forwarding**: The Python relay unicasts the modified DHCPDISCOVER from its server-facing interface (`v_pyrelay_s_ns` on `br_dhcp_test`) to the IP address of the selected Kea DHCPv4 server (e.g., `192.168.10.1` for RED server).
7.  **Kea Server Processing**: The target Kea server (e.g., in `ns_red`):
    *   Receives the relayed packet. It notes the `giaddr`.
    *   Uses the `giaddr` to identify the relevant `shared-networks` block in its configuration.
    *   Parses DHCP Option 82 (specifically the Agent Circuit ID).
    *   Applies its `client-classes` rules. If a class matches (e.g., `VIDEO_USERS_CLASS` for Circuit ID "VIDEO_CIRCUIT"), it selects the subnet/pool associated with that class (e.g., `192.168.10.0/24`).
    *   Allocates an IP and prepares a DHCPOFFER.
8.  **Kea Server Reply**: The Kea server unicasts the DHCPOFFER back to the `giaddr` (which is an IP of our Python relay).
9.  **Relay Receives Offer**: `dhcp_pyrelay.py` receives the DHCPOFFER on its client-facing interface (where the `giaddr` IP is configured).
10. **Relay Strips Option 82**: The relay removes the Option 82 it originally inserted.
11. **Relay Forwards to Client**: The relay broadcasts the DHCPOFFER (now without Option 82) onto `br_clients`.
12. **Client Receives Offer**: The original client receives the DHCPOFFER.
13. *(The DHCPREQUEST/DHCPACK sequence follows a similar relayed path, with the relay performing similar modifications/stripping as appropriate).*

### 4.2. DHCPv6 Client Request (e.g., SOLICIT)

1.  **Client Multicast**: A DHCPv6 client in `ns_client_X` sends a SOLICIT message to the All\_DHCP\_Relay\_Agents\_and\_Servers multicast address (`ff02::1:2`).
2.  **Relay Reception**: `dhcp_pyrelay.py` (in `ns_pyrelay`), having joined the multicast group on `v_pyrelay_c_ns`, receives the SOLICIT. Client source is its Link-Local Address (LLA).
3.  **Relay Policy - VRF Selection**: The Python relay parses the client's DUID (Option 1). It extracts the MAC address if the DUID is DUID-LLT or DUID-LL.
    *   Example: If extracted MAC starts `00:aa:...`, target RED VRF.
    *   Example: If extracted MAC starts `00:bb:...`, target BLUE VRF.
4.  **Relay Policy - Interface-ID Info**: Based on DUID type or further MAC details, the relay determines the value for the Interface-ID option (Option 18) (e.g., "V6\_VIDEO\_LINK" or "V6\_DATA\_LINK").
5.  **Relay Packet Modification (Crafting Relay-Forward)**:
    *   The relay constructs a `Relay-Forward` message.
    *   `msg-type` = 12 (RELAY-FORW).
    *   `hop-count` = 0 (or incremented from incoming if it was already relayed).
    *   `link-address`: An IPv6 address of the relay on the client's link (`v_pyrelay_c_ns`) that corresponds to the target VRF (e.g., if RED VRF, `link-address` might be `fd00:red::fe`).
    *   `peer-address`: The client's source Link-Local Address.
    *   **Options**:
        *   Relay Message option (Option 9): Contains the original client SOLICIT.
        *   Interface-ID option (Option 18): Contains the determined value (e.g., "V6\_VIDEO\_LINK").
6.  **Relay Forwarding**: The Python relay unicasts the `Relay-Forward` message from its server-facing interface (`v_pyrelay_s_ns`) to the IP address of the selected Kea DHCPv6 server (e.g., `fd00:red::1` for RED server).
7.  **Kea Server Processing**: The target Kea server (e.g., in `ns_red`):
    *   Receives the `Relay-Forward`.
    *   Uses the `link-address` to identify the relevant `shared-networks` block.
    *   Extracts the Interface-ID (Option 18) from the `Relay-Forward` message.
    *   Applies its `client-classes` rules. If a class matches (e.g., `V6_VIDEO_USERS_CLASS` for Interface-ID "V6\_VIDEO\_LINK"), it selects the prefix/pool associated with that class (e.g., `fd00:red::/64`).
    *   Prepares an ADVERTISE message (encapsulated later by the server in a Relay-Reply).
8.  **Kea Server Reply (Relay-Reply)**: The Kea server sends a `Relay-Reply` message back to the source IP of the `Relay-Forward` message (the Python relay's server-facing interface IP). The `Relay-Reply` contains the client's original `peer-address` and encapsulates the server's ADVERTISE message (as Option 9).
9.  **Relay Receives Relay-Reply**: `dhcp_pyrelay.py` receives the `Relay-Reply`.
10. **Relay Decapsulation**: It parses the `Relay-Reply`, extracts the encapsulated ADVERTISE message and the `peer-address`.
11. **Relay Forwards to Client**: The relay sends the decapsulated ADVERTISE message to the client's `peer-address` (LLA) on the `br_clients` segment using the correct scope ID.
12. *(The DHCPv6 REQUEST/REPLY sequence follows a similar relayed path).*

## 5. Python Relay Agent Policy Engine (Conceptual)

The "bookkeeping" or policy engine within `dhcp_pyrelay.py` is central to its intelligent behavior.

*   **VRF Selection**:
    *   Input: Client MAC address (from `chaddr` for DHCPv4, or extracted from DUID for DHCPv6).
    *   Logic: A set of rules (initially MAC prefixes `00:AA:...` -> RED, `00:BB:...` -> BLUE) maps the client to a target VRF (RED or BLUE).
    *   Output: Selected VRF ID, target Kea server IPs for that VRF, and the `giaddr`/`link-address` to be used for that VRF.
*   **Intra-VRF Policy (Option Value Selection)**:
    *   Input: Client MAC address, DUID type, selected VRF.
    *   Logic: Further rules determine the specific string value for Option 82 Circuit ID (DHCPv4) or DHCPv6 Interface-ID. This allows differentiation *within* a VRF.
        *   Example for RED VRF: MAC `00:AA:01:...` -> "VIDEO_CIRCUIT". MAC `00:AA:02:...` -> "DATA_CIRCUIT".
        *   Example for RED VRF (DHCPv6): DUID Type 1 -> "V6_VIDEO_LINK". DUID Type 3 -> "V6_DATA_LINK".
    *   Output: The string value to be inserted into the respective DHCP option.
*   **Configuration**: Initially, these policies are hardcoded in `dhcp_pyrelay.py`. For more flexibility, they could be loaded from an external configuration file (e.g., YAML or JSON) in a future iteration.

This design allows the Python relay to act as a sophisticated policy enforcement point, directing traffic and influencing Kea's allocation decisions based on centrally defined rules.

## 6. Project Components & Setup

### 6.1. Scripts
*   **`kea_server_setup.sh`**: Main orchestration script.
    *   Sets up network (bridges, namespaces, veth pairs, IPs).
    *   Generates Kea server configuration files.
    *   Starts/stops Kea server processes.
    *   Starts/stops the `dhcp_pyrelay.py` agent.
    *   Provides cleanup.
*   **`dhcp_pyrelay.py`**: The custom Python DHCPv4/v6 relay agent.
    *   (Development in progress, current version includes argument parsing, logging, daemonization, socket setup for v4/v6, and core relaying logic with Option82/Interface-ID manipulation and VRF selection based on MAC/DUID).
*   **`setup_kea.sh`**: Utility script to install ISC Kea 3.0.0 (including `kea-dhcp4`, `kea-dhcp6`, and `perfdhcp`) from Cloudsmith packages. This is a prerequisite if Kea is not already installed.
*   **`dhcp_simulator.py`**: Client simulator (using `perfdhcp`) developed previously. Can be used to generate test client traffic. It creates its own client namespaces and connects them to a specified bridge (which should be `br_clients` for this setup).

### 6.2. Prerequisites
*   Linux system with root access.
*   `iproute2` package installed.
*   `python3` (for `dhcp_pyrelay.py` and `dhcp_simulator.py`).
    *   Potentially `python3-scapy` if Scapy is chosen for packet manipulation in `dhcp_pyrelay.py` (current implementation uses `struct`).
*   ISC Kea 3.0.0 binaries (`kea-dhcp4`, `kea-dhcp6`, `perfdhcp`). Use `setup_kea.sh` if needed.

### 6.3. Running the Environment

1.  **Initial Kea Installation (if not already done)**:
    ```bash
    chmod +x setup_kea.sh
    sudo ./setup_kea.sh
    ```
2.  **Ensure Scripts are Executable**:
    ```bash
    chmod +x kea_server_setup.sh
    chmod +x dhcp_pyrelay.py
    chmod +x dhcp_simulator.py
    ```
3.  **Start the Full Environment (Servers and Python Relay)**:
    ```bash
    # The PYTHON_RELAY_SCRIPT_PATH in kea_server_setup.sh should point to dhcp_pyrelay.py
    # (e.g., ./dhcp_pyrelay.py if in the same directory)
    sudo ./kea_server_setup.sh start -l debug # Or other log level for the Python relay
    ```
    This command will:
    *   Create all network infrastructure.
    *   Generate Kea server configurations.
    *   Start Kea DHCPv4/v6 servers in `ns_red` and `ns_blue`.
    *   Start the `dhcp_pyrelay.py` agent in `ns_pyrelay`.
    *   Monitor logs in `/tmp/kea_rt/` for each component.

4.  **Run Client Simulations (in a separate terminal)**:
    Use `dhcp_simulator.py` or manual `dhclient` instances in new, temporary client namespaces connected to the `br_clients` bridge.
    *   **Example for RED VRF, VIDEO policy (DHCPv4)**:
        ```bash
        sudo python3 dhcp_simulator.py \
            --num-clients 5 \
            --host-iface br_clients \
            --base-mac 00:aa:01:00:00:00 \
            --dhcpv4-server 255.255.255.255 `# Target broadcast for relay pickup` \
            --duration 60 --rate 2 \
            --output-dir ./sim_logs_red_video
        ```
    *   **Example for BLUE VRF, DATA policy (DHCPv4)**:
        ```bash
        sudo python3 dhcp_simulator.py \
            --num-clients 5 \
            --host-iface br_clients \
            --base-mac 00:bb:02:00:00:00 \
            --dhcpv4-server 255.255.255.255 \
            --duration 60 --rate 2 \
            --output-dir ./sim_logs_blue_data
        ```
    *   *(Similar invocations can be made for DHCPv6 by specifying `--dhcpv6-server ff02::1:2` and appropriate `--base-mac` which influences DUID generation by perfdhcp).*

5.  **Monitor and Verify**:
    *   Python Relay Logs: `/tmp/kea_rt/ns_pyrelay/pyrelay.log`
    *   Kea Server Logs: `/tmp/kea_rt/ns_red/kea-dhcp4-server.log`, etc.
    *   Kea Lease Files: `/tmp/kea_rt/ns_red/kea-leases4.csv`, etc.
    *   `dhcp_simulator.py` console output and its log directory.
    *   `tcpdump` on `br_clients`, `br_dhcp_test`, and inside namespaces for detailed packet flow.

6.  **Stop and Cleanup**:
    ```bash
    sudo ./kea_server_setup.sh stop      # Stops Kea servers and Python relay
    sudo ./kea_server_setup.sh cleanup   # Stops processes and removes all network setup & runtime files
    ```

## 7. End-to-End Testing with `run_e2e_tests.sh`

An automated end-to-end test script, `run_e2e_tests.sh`, is provided to orchestrate the setup, execution of predefined test cases, basic verification, and cleanup of the entire environment.

### 7.1. Purpose
The `run_e2e_tests.sh` script aims to:
*   Automate the startup of the Kea servers and Python relay.
*   Run a series of DHCPv4 and DHCPv6 test scenarios using `dhcp_simulator.py` with specific client MACs/DUIDs.
*   Perform basic verification of test success by checking `perfdhcp` client logs for lease acquisition.
*   Automate the cleanup of the environment.
*   Provide a summary of test pass/fail status.

### 7.2. Prerequisites
*   All prerequisites for the main environment (see Section 6.2).
*   The `run_e2e_tests.sh`, `kea_server_setup.sh`, `dhcp_pyrelay.py`, and `dhcp_simulator.py` scripts should be in the same directory and executable.

### 7.3. Usage
```bash
sudo ./run_e2e_tests.sh [options]
```
**Options:**
*   `-p /path/to/perfdhcp`: Specify a custom path to the `perfdhcp` executable if it's not at the default `/usr/sbin/perfdhcp`.
*   `-d`: Enable debug mode. This provides more verbose logging from the test wrapper script itself, including commands being executed and detailed verification steps.
*   `--no-cleanup`: If this flag is present, the script will skip the final cleanup step (`kea_server_setup.sh cleanup`). This is useful for debugging, as it leaves the network environment and logs intact for manual inspection after the tests have run.

### 7.4. Test Cases Covered
The script currently executes the following predefined test cases:
*   **DHCPv4 RED VRF - VIDEO Policy**: Client MAC `00:aa:01:...`, expects IP from `192.168.10.0/24`.
*   **DHCPv4 RED VRF - DATA Policy**: Client MAC `00:aa:02:...`, expects IP from `192.168.11.0/24`.
*   **DHCPv4 BLUE VRF - Generic**: Client MAC `00:bb:01:...`, expects IP from `192.168.20.0/24`.
*   **DHCPv6 RED VRF - VIDEO Policy**: Client DUID (LLT based on MAC `00:aa:01:...`), expects IP from `fd00:red::/64`.
*   **DHCPv6 RED VRF - DATA Policy**: Client DUID (LLT based on MAC `00:aa:02:...`), expects IP from `fd00:red:1::/64`.
*   **DHCPv6 BLUE VRF - Generic**: Client DUID (LLT based on MAC `00:bb:01:...`), expects IP from `fd00:blue::/64`.

### 7.5. Output
*   The script logs its actions to standard output.
*   `dhcp_simulator.py` (and thus `perfdhcp`) logs for each test run are stored in timestamped subdirectories under `e2e_test_results/`.
*   A final summary of PASSED/FAILED tests is printed.
*   The script exits with 0 if all tests pass, and 1 otherwise.

### 7.6. Verification Logic
Verification for each test case is primarily based on analyzing the output log from `perfdhcp` (via `dhcp_simulator.py`):
1.  **Log File Existence**: Checks if the `perfdhcp` log file was created.
2.  **"tests complete"**: Ensures `perfdhcp` reported completion.
3.  **Leases Obtained**: Verifies that `perfdhcp` reported acquiring at least one lease.
4.  **Error Indicators**: Checks for common error strings (e.g., "timeout", "failed to receive", "no offer") in the `perfdhcp` log. If such errors are found and no leases were obtained, the test is marked as failed. If errors are present but leases were obtained, a warning is issued.
5.  **Subnet Pattern (Informational)**: A basic check for an expected IP subnet pattern within the log. Due to default `perfdhcp` logging behavior, not finding this pattern does not automatically fail the test if other criteria are met.

For detailed debugging of relay or Kea server behavior, manual inspection of their respective logs (e.g., `/tmp/kea_rt/ns_pyrelay/pyrelay.log`, `/tmp/kea_rt/ns_red/*`) is still recommended, especially if a test case fails.

## 8. Future Enhancements / Considerations
*   **Configurable Python Relay Policy**: Load relay policies (MAC/DUID to VRF mapping, Option 82/Interface-ID values) from an external file (YAML/JSON) instead of hardcoding in `dhcp_pyrelay.py`.
*   **Advanced Packet Manipulation**: Use a library like Scapy in `dhcp_pyrelay.py` for more complex DHCP option handling if needed.
*   **Performance Optimization for Python Relay**: If `select`-based loop becomes a bottleneck under very high load, explore `asyncio` or multiprocessing/threading models.
*   **DHCPv6 DUID Policy Refinement**: Allow more flexible DUID-based policies beyond just DUID type and embedded MAC.
*   **Automated `tcpdump`**: Integrate `tcpdump` start/stop into `kea_server_setup.sh` for easier debugging.
*   **Security**: The current setup runs processes with `sudo` and has permissive chmod on runtime directories. For any non-testing use, proper user accounts and permissions for Kea and the relay agent would be essential.

This README provides a solid overview of the current project state and future direction.
