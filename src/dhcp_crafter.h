#ifndef DHCP_CRAFTER_H
#define DHCP_CRAFTER_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/**
 * @brief Defines the states for the DHCP client state machine.
 */
typedef enum {
    STATE_INIT,
    STATE_V4_DISCOVER_SENT,
    STATE_V4_REQUEST_SENT,
    STATE_V6_SOLICIT_SENT,
    STATE_V6_REQUEST_SENT,
    STATE_DONE,
    STATE_FAILED
} client_state_t;

/**
 * @brief Represents a single simulated DHCP client.
 */
typedef struct {
    int client_index;
    uint8_t mac_addr[6];
    char vci[64];

    // --- IPv4-specific state ---
    client_state_t state_v4;
    uint32_t xid_v4;
    long long last_sent_time_v4_ms;
    char leased_ipv4[16];
    uint32_t server_id_v4;
    uint32_t offered_ip_v4;

    // --- IPv6-specific state ---
    client_state_t state_v6;
    uint32_t xid_v6;
    long long last_sent_time_v6_ms;
    char leased_ipv6[INET6_ADDRSTRLEN];
    uint8_t server_duid_v6[128];
    size_t server_duid_len_v6;

} simulated_client;

/**
 * @brief Public API function to run the entire DHCPv4 simulation.
 * @param if_name The network interface to use.
 * @param clients An array of client structures to simulate.
 * @param num_clients The number of clients in the array.
 * @return The number of clients that successfully acquired a lease.
 */
int perform_concurrent_dhcpv4 (const char *if_name, simulated_client *clients, int num_clients);

/**
 * @brief Public API function to run the entire DHCPv6 simulation.
 * @param if_name The network interface to use.
 * @param clients An array of client structures to simulate.
 * @param num_clients The number of clients in the array.
 * @return The number of clients that successfully acquired a lease.
 */
int perform_concurrent_dhcpv6 (const char *if_name, simulated_client *clients, int num_clients);

#endif // DHCP_CRAFTER_H