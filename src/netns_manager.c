#define _GNU_SOURCE
#include "netns_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h> // For perror and strerror

// --- Internal Helper Prototypes ---
static int check_command(const char* cmd, const char* success_msg);
static int is_interface_ready(const char* ns_name, const char* if_name);
// New prototype for comprehensive offloading disable
static int disable_all_offloading(const char* if_name);

/**
 * @brief Sets up a complete network namespace environment.
 *
 * This function is self-contained and performs all necessary steps:
 * 1. Creates the namespace and veth pair.
 * 2. Moves the peer interface into the namespace.
 * 3. Disables IPv6 DAD for stability in test environments.
 * 4. Assigns multiple IPv4 and IPv6 addresses.
 * 5. Brings BOTH ends of the veth pair up.
 * 6. Disables ALL checksum/segmentation offloading.
 * 7. Polls and waits until the interface is fully operational.
 *
 * @return 0 on success, -1 on failure.
 */
int setup_namespace_environment(const char* ns_name, const char* veth_root, const char* veth_ns,
                                const char* ipv4_ns_1, const char* ipv6_ns_1,
                                const char* ipv4_ns_2, const char* ipv6_ns_2) {
    char cmd[512];

    printf("\n[+] Configuring %s namespace...\n", ns_name);

    snprintf(cmd, sizeof(cmd), "ip netns add %s", ns_name);
    if (check_command(cmd, "Namespace created.") != 0) return -1;

    snprintf(cmd, sizeof(cmd), "ip link add %s type veth peer name %s", veth_root, veth_ns);
    if (check_command(cmd, "Veth pair created.") != 0) return -1;

    snprintf(cmd, sizeof(cmd), "ip link set %s netns %s", veth_ns, ns_name);
    if (check_command(cmd, "Peer moved to namespace.") != 0) return -1;

    snprintf(cmd, sizeof(cmd), "ip netns exec %s sysctl -w net.ipv6.conf.%s.accept_dad=0", ns_name, veth_ns);
    if (check_command(cmd, "DAD disabled.") != 0) return -1;

    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip addr add %s dev %s", ns_name, ipv4_ns_1, veth_ns);
    if (check_command(cmd, "Primary IPv4 added.") != 0) return -1;
    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip addr add %s dev %s", ns_name, ipv6_ns_1, veth_ns);
    if (check_command(cmd, "Primary IPv6 added.") != 0) return -1;
    if (ipv4_ns_2) {
        snprintf(cmd, sizeof(cmd), "ip netns exec %s ip addr add %s dev %s", ns_name, ipv4_ns_2, veth_ns);
        if (check_command(cmd, "Secondary IPv4 added.") != 0) return -1;
    }
    if (ipv6_ns_2) {
        snprintf(cmd, sizeof(cmd), "ip netns exec %s ip addr add %s dev %s", ns_name, ipv6_ns_2, veth_ns);
        if (check_command(cmd, "Secondary IPv6 added.") != 0) return -1;
    }

    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip link set %s up", ns_name, veth_ns);
    if (check_command(cmd, "Namespace-side link is UP.") != 0) return -1;

    snprintf(cmd, sizeof(cmd), "ip link set %s up", veth_root);
    if (check_command(cmd, "Root-side link is UP.") != 0) return -1;

    // --- NEW: Disable ALL offloading on both sides of the veth pair ---
    // This is more comprehensive to tackle elusive checksum or segmentation offloading issues.
    if (disable_all_offloading(veth_root) != 0) {
        fprintf(stderr, "FATAL: Failed to disable ALL offloading on %s.\n", veth_root);
        return -1;
    }
    snprintf(cmd, sizeof(cmd), "ip netns exec %s ethtool -K %s rx off tx off sg off tso off gso off gro off lro off", ns_name, veth_ns);
    if (check_command(cmd, "ALL offloading disabled for namespace side.") != 0) {
        fprintf(stderr, "FATAL: Could not disable ALL offloading for %s inside %s.\n", veth_ns, ns_name);
        return -1;
    }
    // --- END NEW ---


    // Tell the kernel's IPv6 stack to ignore this interface for autoconfiguration
    printf("    - Disabling kernel IPv6 autoconf on '%s' (root side)\n", veth_root);
    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv6.conf.%s.autoconf=0", veth_root);
    if (check_command(cmd, "Kernel autoconf disabled.") != 0) return -1;

    if (!is_interface_ready(ns_name, veth_ns)) {
        return -1;
    }

    return 0;
}

/**
 * @brief Deletes a network namespace.
 * This is safe to call even if the namespace does not exist.
 */
void cleanup_namespace_environment(const char* ns_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip netns del %s > /dev/null 2>&1", ns_name);
    system(cmd);
}

/**
 * @brief Runs a command inside a specific network namespace.
 */
void run_command_in_ns(const char* ns_name, const char* command) {
    char full_command[1024];
    snprintf(full_command, sizeof(full_command), "ip netns exec %s sh -c '%s'", ns_name, command);
    if (system(full_command) != 0) {
        fprintf(stderr, "    [ERROR] Command failed: %s\n", full_command);
    }
}

/**
 * @brief Executes a shell command and checks its exit code.
 *
 * This helper function provides strict error checking for all setup commands.
 * It also suppresses command output for a cleaner log.
 *
 * @return 0 on success, -1 on failure.
 */
static int check_command(const char* cmd, const char* success_msg) {
    printf("    - Executing: %s\n", cmd);
    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd), "%s > /dev/null 2>&1", cmd);

    if (system(full_cmd) != 0) {
        fprintf(stderr, "    [FATAL] Command failed! Check permissions or pre-existing state. Command: %s\n", cmd);
        return -1;
    }
    if (success_msg) {
        printf("      > %s\n", success_msg);
    }
    return 0;
}

/**
 * @brief Polls an interface inside a namespace until it is fully ready.
 *
 * A ready interface is defined as having link state UP and a "preferred"
 * link-local IPv6 address. This is critical for ensuring DHCP servers can
 * bind to the interface without errors.
 *
 * @return 1 if the interface becomes ready, 0 on timeout.
 */
static int is_interface_ready(const char* ns_name, const char* if_name) {
    char cmd[512];
    printf("    - Verifying link state and IPv6 readiness for '%s'...\n", if_name);

    for (int i = 0; i < 20; i++) { // Poll for up to 4 seconds
        char check_up_cmd[256];
        char check_ipv6_cmd[256];

        snprintf(check_up_cmd, sizeof(check_up_cmd),
                 "ip netns exec %s ip link show dev %s | grep -q 'state UP'", ns_name, if_name);

        snprintf(check_ipv6_cmd, sizeof(check_ipv6_cmd),
                 "ip netns exec %s ip addr show dev %s | grep 'inet6 fe80' | grep -q 'scope link'", ns_name, if_name);

        // Both conditions must be true for the interface to be considered ready
        if (system(check_up_cmd) == 0 && system(check_ipv6_cmd) == 0) {
            printf("      > Interface is ready.\n");
            return 1;
        }

        usleep(200000); // Wait 200ms before retrying
    }

    fprintf(stderr, "    [FATAL] Timeout waiting for interface to become ready.\n");
    fprintf(stderr, "      > Final state of '%s' in namespace '%s':\n", if_name, ns_name);
    snprintf(cmd, sizeof(cmd), "ip netns exec %s ip addr show dev %s", ns_name, if_name);
    system(cmd);
    return 0;
}

/**
 * @brief Disables all major checksum and segmentation offloading for a given interface.
 *
 * This is crucial for virtual interfaces like veth pairs in simulation
 * environments, as offloading can cause "bad checksum" errors or prevent
 * packets from being seen correctly by software sniffers or applications
 * that perform their own checksum validation.
 *
 * @param if_name The name of the interface.
 * @return 0 on success, -1 on failure.
 */
static int disable_all_offloading(const char* if_name) {
    char cmd[256];
    printf("    - Disabling ALL offloading for '%s'...\n", if_name);
    // Comprehensive disable: rx/tx checksumming, scatter-gather, TCP/UDP segmentation, generic segmentation, generic receive, large receive.
    snprintf(cmd, sizeof(cmd), "ethtool -K %s rx off tx off sg off tso off gso off gro off lro off", if_name);
    if (system(cmd) != 0) {
        // ethtool might return non-zero if some offloads aren't supported (e.g., on older kernels or virtual devices)
        // or if the interface is not a real device.
        fprintf(stderr, "    [WARNING] Failed to disable all offloading for %s. This might be expected on some virtual interfaces if features are not present. Error: %s\n", if_name, strerror(errno));
        // We'll proceed with a warning, but this could still be the root cause if critical offloads remain active.
        return 0;
    }
    printf("      > ALL offloading disabled.\n");
    return 0;
}