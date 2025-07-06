/**
 * @file main.c
 * @brief Main application to orchestrate the network namespace simulation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <linux/limits.h>

#include "netns_manager.h"
#include "dhcp_crafter.h"

// --- Configuration Constants ---
#define NUM_CLIENTS_PER_NS 2

// --- Network Topology Constants ---
#define NS_RED "red"
#define NS_BLUE "blue"
#define VETH_ROOT_RED "veth-r-red"
#define VETH_NS_RED "veth-ns-red"
#define VETH_ROOT_BLUE "veth-r-blue"
#define VETH_NS_BLUE "veth-ns-blue"

// --- IP Address Definitions for Server Interfaces ---
#define IPV4_NS_RED_1 "10.10.10.2/24"
#define IPV6_NS_RED_1 "fd10:10:10::2/64"
#define IPV4_NS_RED_2 "10.10.11.2/24"
#define IPV6_NS_RED_2 "fd10:10:11::2/64"

#define IPV4_NS_BLUE_1 "10.20.10.2/24"
#define IPV6_NS_BLUE_1 "fd10:20:10::2/64"
#define IPV4_NS_BLUE_2 "10.20.11.2/24"
#define IPV6_NS_BLUE_2 "fd10:20:11::2/64"

// --- KEA Config File Paths (relative names) ---
#define KEA_CONF_DIR "conf"
#define KEA_V4_RED_FNAME "red-kea-dhcp4.conf"
#define KEA_V6_RED_FNAME "red-kea-dhcp6.conf"
#define KEA_V4_BLUE_FNAME "blue-kea-dhcp4.conf"
#define KEA_V6_BLUE_FNAME "blue-kea-dhcp6.conf"

// --- Global for executable path ---
static char executable_dir[PATH_MAX];

// --- Function Prototypes ---
void setup_all_environments();
void run_all_simulations();
void cleanup_all_environments();
void initialize_clients (simulated_client *clients, int num_clients, const char *name_prefix, uint8_t mac_prefix);
void start_packet_captures();
void stop_packet_captures();
int find_executable_dir();

int main (int argc, char *argv[])
{
    if (geteuid() != 0) {
        fprintf (stderr, "This program must be run as root. Please use the 'build.sh' script.\n");
        return 1;
    }
    srand (time (NULL));

    if (find_executable_dir() != 0) {
        fprintf (stderr, "Could not determine executable directory. Aborting.\n");
        return 1;
    }

    cleanup_all_environments();
    setup_all_environments();
    start_packet_captures();

    // ADD THESE LINES TO PAUSE EXECUTION
    printf ("\n\n>>> Setup complete. Kea servers and packet captures are running. <<<\n");
    printf (">>> Press Enter to start client simulations, or Ctrl+C to stop and debug. <<<\n");
    getchar();

    run_all_simulations();
    stop_packet_captures();

    printf ("\n\n\e[1;32m>>> ALL SIMULATIONS COMPLETE. <<<\e[0m\n");
    printf (">>> PCAP files saved to 'red_capture.pcap' and 'blue_capture.pcap'. <<<\n");
    printf (">>> Press Enter to cleanup and exit. <<<\n");
    getchar();

    cleanup_all_environments();
    printf ("\nEnvironment cleaned up successfully.\n");
    return 0;
}

void setup_all_environments()
{
    printf ("\n\e[1;34m--- Phase 1: Setting up Network Environments ---\e[0m\n");

    printf ("\n[+] Configuring red namespace...\n");
    if (setup_namespace_environment (NS_RED, VETH_ROOT_RED, VETH_NS_RED, IPV4_NS_RED_1, IPV6_NS_RED_1, IPV4_NS_RED_2, IPV6_NS_RED_2) != 0) {
        fprintf (stderr, "FATAL: Failed to setup environment for %s. Aborting.\n", NS_RED); cleanup_all_environments(); exit (1);
    }
    printf ("[+] Namespace %s is ready.\n", NS_RED);

    printf ("\n[+] Configuring blue namespace...\n");
    if (setup_namespace_environment (NS_BLUE, VETH_ROOT_BLUE, VETH_NS_BLUE, IPV4_NS_BLUE_1, IPV6_NS_BLUE_1, IPV4_NS_BLUE_2,
                                    IPV6_NS_BLUE_2) != 0) {
        fprintf (stderr, "FATAL: Failed to setup environment for %s. Aborting.\n", NS_BLUE); cleanup_all_environments(); exit (1);
    }
    printf ("[+] Namespace %s is ready.\n", NS_BLUE);

    printf ("\n\e[1m[+] Starting all KEA DHCP servers...\e[0m\n");
    char cmd[PATH_MAX + 128];
    // --- FIX: Use absolute path for config files ---
    snprintf (cmd, sizeof (cmd), "kea-dhcp4 -c %s/%s/%s &", executable_dir, KEA_CONF_DIR, KEA_V4_RED_FNAME); run_command_in_ns (NS_RED, cmd);
    snprintf (cmd, sizeof (cmd), "kea-dhcp6 -c %s/%s/%s &", executable_dir, KEA_CONF_DIR, KEA_V6_RED_FNAME); run_command_in_ns (NS_RED, cmd);
    snprintf (cmd, sizeof (cmd), "kea-dhcp4 -c %s/%s/%s &", executable_dir, KEA_CONF_DIR, KEA_V4_BLUE_FNAME); run_command_in_ns (NS_BLUE, cmd);
    snprintf (cmd, sizeof (cmd), "kea-dhcp6 -c %s/%s/%s &", executable_dir, KEA_CONF_DIR, KEA_V6_BLUE_FNAME); run_command_in_ns (NS_BLUE, cmd);

    printf ("    - Waiting for servers to initialize...\n");
    sleep (5);
}

void run_all_simulations()
{
    simulated_client red_clients[NUM_CLIENTS_PER_NS];
    simulated_client blue_clients[NUM_CLIENTS_PER_NS];

    printf ("\n\e[1;34m--- Phase 2: Running Concurrent Client Simulations ---\e[0m\n");
    printf ("\n\e[1m[+] Simulating clients in RED namespace...\e[0m\n");
    initialize_clients (red_clients, NUM_CLIENTS_PER_NS, "red-client-class", 0x01);
    perform_concurrent_dhcpv4 (VETH_ROOT_RED, red_clients, NUM_CLIENTS_PER_NS);
    initialize_clients (red_clients, NUM_CLIENTS_PER_NS, "red-client-class", 0x01);
    perform_concurrent_dhcpv6 (VETH_ROOT_RED, red_clients, NUM_CLIENTS_PER_NS);

    printf ("\n\e[1m[+] Simulating clients in BLUE namespace...\e[0m\n");
    initialize_clients (blue_clients, NUM_CLIENTS_PER_NS, "blue-client-class", 0x02);
    perform_concurrent_dhcpv4 (VETH_ROOT_BLUE, blue_clients, NUM_CLIENTS_PER_NS);
    initialize_clients (blue_clients, NUM_CLIENTS_PER_NS, "blue-client-class", 0x02);
    perform_concurrent_dhcpv6 (VETH_ROOT_BLUE, blue_clients, NUM_CLIENTS_PER_NS);

    printf ("\n\e[1;34m--- Phase 3: Simulation Results ---\e[0m\n");
}

void cleanup_all_environments()
{
    printf ("\n\e[1;34m--- Forcefully Tearing Down All Environments ---\e[0m\n");
    printf ("    - Stopping any lingering Kea DHCP servers...\n");
    system ("pkill -f kea-dhcp4 > /dev/null 2>&1");
    system ("pkill -f kea-dhcp6 > /dev/null 2>&1");
    sleep (1);
    printf ("    - Deleting network namespace '%s' (if it exists)...\n", NS_RED);
    cleanup_namespace_environment (NS_RED);
    printf ("    - Deleting network namespace '%s' (if it exists)...\n", NS_BLUE);
    cleanup_namespace_environment (NS_BLUE);
    printf ("    - Deleting root veth pairs (if they exist)...\n");
    system ("ip link del " VETH_ROOT_RED " > /dev/null 2>&1");
    system ("ip link del " VETH_ROOT_BLUE " > /dev/null 2>&1");
    system ("rm -f tcpdump_red.pid tcpdump_blue.pid");
    printf ("    - Cleanup complete.\n");
}

void initialize_clients (simulated_client *clients, int num_clients, const char *name_prefix, uint8_t mac_prefix)
{
    for (int i = 0; i < num_clients; i++) {
        clients[i].client_index = i + 1;
        uint8_t base_mac[6] = {0x00, 0xDE, 0xAD, 0xBE, mac_prefix, (uint8_t) (i + 1) };
        memcpy (clients[i].mac_addr, base_mac, 6);
        snprintf (clients[i].vci, sizeof (clients[i].vci), "%s-%d", name_prefix, i + 1);
        clients[i].state_v4 = STATE_INIT;
        clients[i].state_v6 = STATE_INIT;
        memset (clients[i].leased_ipv4, 0, sizeof (clients[i].leased_ipv4));
        memset (clients[i].leased_ipv6, 0, sizeof (clients[i].leased_ipv6));
        clients[i].last_sent_time_v4_ms = - (rand() % 1000);
        clients[i].last_sent_time_v6_ms = - (rand() % 1000);
    }
}

// ===================================================================================
// Packet Capture Functions
// ===================================================================================

void start_packet_captures()
{
    char cmd[256];
    printf ("\n\e[1;35m--- Starting Packet Captures ---\e[0m\n");

    printf ("    - Starting tcpdump on '%s' -> red_capture.pcap\n", VETH_ROOT_RED);
    snprintf (cmd, sizeof (cmd), "tcpdump -i %s -w red_capture.pcap -U & echo $! > tcpdump_red.pid", VETH_ROOT_RED);
    system (cmd);

    printf ("    - Starting tcpdump on '%s' -> blue_capture.pcap\n", VETH_ROOT_BLUE);
    snprintf (cmd, sizeof (cmd), "tcpdump -i %s -w blue_capture.pcap -U & echo $! > tcpdump_blue.pid", VETH_ROOT_BLUE);
    system (cmd);

    sleep (1);
}

void stop_packet_captures()
{
    FILE *f_pid;
    pid_t pid;

    printf ("\n\e[1;35m--- Stopping Packet Captures ---\e[0m\n");

    if ( (f_pid = fopen ("tcpdump_red.pid", "r"))) {
        if (fscanf (f_pid, "%d", &pid) > 0) {
            printf ("    - Stopping tcpdump for RED (PID: %d)...\n", pid);
            kill (pid, SIGINT);
        }
        fclose (f_pid);
    }

    if ( (f_pid = fopen ("tcpdump_blue.pid", "r"))) {
        if (fscanf (f_pid, "%d", &pid) > 0) {
            printf ("    - Stopping tcpdump for BLUE (PID: %d)...\n", pid);
            kill (pid, SIGINT);
        }
        fclose (f_pid);
    }

    sleep (1);
}

int find_executable_dir()
{
    char path[PATH_MAX];
    ssize_t len = readlink ("/proc/self/exe", path, sizeof (path) - 1);
    if (len == -1) {
        perror ("readlink");
        return -1;
    }
    path[len] = '\0';
    char *dir = dirname (path);
    if (dir == NULL) {
        perror ("dirname");
        return -1;
    }
    strncpy (executable_dir, dir, sizeof (executable_dir) - 1);
    executable_dir[sizeof (executable_dir) - 1] = '\0';
    return 0;
}
