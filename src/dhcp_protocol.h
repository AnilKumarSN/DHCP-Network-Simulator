#ifndef DHCP_PROTOCOL_H
#define DHCP_PROTOCOL_H

#include "dhcp_crafter.h"
#include <netinet/in.h>

// ============================================================================
// SHARED CONSTANTS
// ============================================================================

#define DHCP_V4_RETRY_MS 3000
#define DHCP_V6_RETRY_MS 3000
#define DHCP_SERVER_PORT_V4 67
#define DHCP_CLIENT_PORT_V4 68
#define DHCP_SERVER_PORT_V6 547
#define DHCP_CLIENT_PORT_V6 546

#define DHCP_GLOBAL_TIMEOUT_S 15 // Timeout for the entire simulation loop
#define MAX_EPOLL_EVENTS 50      // Max events to retrieve from epoll_wait

// ============================================================================
// INTERNAL HANDLER FUNCTION PROTOTYPES
// ============================================================================

// --- DHCPv4 Handlers (implemented in dhcp_protocol_v4.c) ---

/**
 * @brief Handles the "action" phase for a single DHCPv4 client (sends/retries).
 */
void handle_dhcpv4_action (int sock_fd, int if_index, simulated_client *client);

/**
 * @brief Handles an incoming packet for a single DHCPv4 client.
 */
void handle_dhcpv4_reply (const uint8_t *buffer, ssize_t len, simulated_client *client, int sock_fd, int if_index);


// --- DHCPv6 Handlers (implemented in dhcp_protocol_v6.c) ---

/**
 * @brief Handles the "action" phase for a single DHCPv6 client (sends/retries).
 */
void handle_dhcpv6_action (int sock_fd, int if_index, simulated_client *client, const struct in6_addr *ll_addr);

/**
 * @brief Handles an incoming packet for a single DHCPv6 client.
 */
void handle_dhcpv6_reply (const uint8_t *buffer, ssize_t len, simulated_client *client, int sock_fd, int if_index,
                const struct in6_addr *ll_addr);


// --- Shared Simulation Loop (implemented in dhcp_client.c) ---

/**
 * @brief The main event loop that drives a simulation for a given protocol.
 */
int run_simulation_loop (const char *if_name, simulated_client *clients, int num_clients, int protocol);


#endif // DHCP_PROTOCOL_H