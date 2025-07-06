/**
 * @file dhcp_protocol_v6.c
 * @brief Standalone, robust DHCPv6 client using AF_INET6 UDP sockets.
 *
 * This is the architecturally correct implementation to handle unicast replies
 * from the DHCPv6 server and avoid ICMP Port Unreachable errors.
 */

#include "dhcp_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h> // For getifaddrs
#include <netinet/in.h> // For struct ipv6_mreq

#pragma pack(push, 1)
typedef struct { uint8_t msg_type; uint8_t xid[3]; } dhcp_packet_v6;
typedef struct { uint16_t code; uint16_t len; } dhcp_option_v6;
#pragma pack(pop)

// Internal helpers for this file
static long long get_current_time_ms_v6();
static uint8_t *add_dhcp_option_v6 (uint8_t *opt, uint16_t code, uint16_t len, const void *data);
static int build_and_send_v6_packet (int sock_fd, int if_index, simulated_client *client, uint8_t msg_type);
static void parse_dhcp_reply_v6 (const uint8_t *options, ssize_t options_len, simulated_client *client);
static int create_and_bind_udp_socket (const char *if_name, int *if_index_out);

// --- Public API Function ---

int perform_concurrent_dhcpv6 (const char *if_name, simulated_client *clients, int num_clients)
{
    printf ("\n\e[1m[+] Starting concurrent DHCPv6 simulation for %d clients on %s...\e[0m\n", num_clients, if_name);

    int sock_fd, if_index;
    if ( (sock_fd = create_and_bind_udp_socket (if_name, &if_index)) < 0) {
        return -1;
    }

    int epoll_fd = epoll_create1 (0);
    if (epoll_fd < 0) {
        perror ("epoll_create1");
        close (sock_fd);
        return -1;
    }
    struct epoll_event event = {.data.fd = sock_fd, .events = EPOLLIN};
    if (epoll_ctl (epoll_fd, EPOLL_CTL_ADD, sock_fd, &event) < 0) {
        perror ("epoll_ctl");
        close (epoll_fd);
        close (sock_fd);
        return -1;
    }

    for (int i = 0; i < num_clients; i++) {
        clients[i].state_v6 = STATE_INIT;
        clients[i].xid_v6 = rand() & 0x00FFFFFF;
        clients[i].last_sent_time_v6_ms = 0;
        memset (clients[i].leased_ipv6, 0, sizeof (clients[i].leased_ipv6));
        memset (clients[i].server_duid_v6, 0, sizeof (clients[i].server_duid_v6));
        clients[i].server_duid_len_v6 = 0;
    }

    long long start_time = time (NULL);
    int completed_clients = 0;

    while (completed_clients < num_clients && time (NULL) - start_time < DHCP_GLOBAL_TIMEOUT_S) { // Use global timeout
        for (int i = 0; i < num_clients; i++) {
            // Passing NULL for ll_addr as it's not needed for UDP socket sending (kernel handles source IP)
            handle_dhcpv6_action (sock_fd, if_index, &clients[i], NULL);
        }

        struct epoll_event events[MAX_EPOLL_EVENTS]; // Use MAX_EPOLL_EVENTS
        int num_events = epoll_wait (epoll_fd, events, MAX_EPOLL_EVENTS, 200);
        for (int i = 0; i < num_events; i++) {
            uint8_t buffer[2048];
            ssize_t len = recv (sock_fd, buffer, sizeof (buffer), 0);
            if (len > 0) {
                const dhcp_packet_v6 *dhcp = (const dhcp_packet_v6 *) buffer;
                // Verify XID to dispatch to the correct client
                uint32_t xid = (dhcp->xid[0] << 16) | (dhcp->xid[1] << 8) | dhcp->xid[2];
                for (int j = 0; j < num_clients; j++) {
                    if (clients[j].xid_v6 == xid) {
                        handle_dhcpv6_reply (buffer, len, &clients[j], sock_fd, if_index, NULL); // ll_addr not needed here either
                        break; // Packet handled
                    }
                }
            }
        }

        completed_clients = 0;
        for (int i = 0; i < num_clients; i++) {
            if (clients[i].state_v6 >= STATE_DONE) {
                completed_clients++;
            }
        }
    }

    close (sock_fd); close (epoll_fd);

    int successful_clients = 0;
    for (int i = 0; i < num_clients; i++) {
        if (clients[i].state_v6 == STATE_DONE) {
            successful_clients++;
        }
    }
    printf ("[+] DHCPv6 simulation finished. \e[1;32m%d\e[0m/\e[1m%d\e[0m clients succeeded.\n", successful_clients, num_clients);
    return successful_clients;
}

// --- Internal Handlers ---

void handle_dhcpv6_action (int sock_fd, int if_index, simulated_client *client, const struct in6_addr *ll_addr)
{
    (void) ll_addr; // Not needed for UDP socket version
    long long now = get_current_time_ms_v6();
    if (client->state_v6 != STATE_DONE && client->state_v6 != STATE_FAILED) {
        if (client->state_v6 == STATE_INIT || (client->state_v6 == STATE_V6_SOLICIT_SENT &&
                                        now - client->last_sent_time_v6_ms > DHCP_V6_RETRY_MS)) {
            if (client->state_v6 == STATE_V6_SOLICIT_SENT) {
                printf ("  [RETRY] Client %d (v6) SOLICIT\n", client->client_index);
            }
            build_and_send_v6_packet (sock_fd, if_index, client, 1); // SOLICIT
            client->state_v6 = STATE_V6_SOLICIT_SENT;
            client->last_sent_time_v6_ms = now;
        }
    }
}

void handle_dhcpv6_reply (const uint8_t *buffer, ssize_t len, simulated_client *client, int sock_fd, int if_index,
                const struct in6_addr *ll_addr)
{
    (void) ll_addr; // Not needed for UDP socket version
    if ( (size_t) len < sizeof (dhcp_packet_v6)) {
        return;
    }
    const dhcp_packet_v6 *dhcp = (const dhcp_packet_v6 *) buffer;

    // Check if client is already done or failed, or if XID doesn't match
    // (XID check for dispatch is already done in perform_concurrent_dhcpv6 loop)
    if (client->state_v6 >= STATE_DONE) {
        return;
    }

    const uint8_t *options_ptr = (const uint8_t *) (dhcp + 1);
    ssize_t options_len = len - sizeof (dhcp_packet_v6);

    if (client->state_v6 == STATE_V6_SOLICIT_SENT && dhcp->msg_type == 2) { // ADVERTISE
        printf ("  [RX] Client %d (v6): Received ADVERTISE\n", client->client_index);
        parse_dhcp_reply_v6 (options_ptr, options_len, client);
        // Only send REQUEST if we successfully parsed a server DUID AND an offered IP (IA_ADDR)
        // Check for leased_ipv6 not being empty to ensure an address was offered
        if (client->server_duid_len_v6 > 0 && strlen (client->leased_ipv6) > 0) {
            printf ("  [ACTION] Client %d (v6): Sending REQUEST\n", client->client_index);
            build_and_send_v6_packet (sock_fd, if_index, client, 3); // REQUEST
            client->state_v6 = STATE_V6_REQUEST_SENT;
            client->last_sent_time_v6_ms = get_current_time_ms_v6();
        } else {
            fprintf (stderr, "  [FAIL] Client %d (v6): Received ADVERTISE but no Server DUID or no address offered.\n", client->client_index);
            client->state_v6 = STATE_FAILED;
        }
    } else if (client->state_v6 == STATE_V6_REQUEST_SENT && dhcp->msg_type == 7) { // REPLY
        printf ("  [RX] Client %d (v6): Received REPLY\n", client->client_index);
        parse_dhcp_reply_v6 (options_ptr, options_len, client);
        if (strlen (client->leased_ipv6) > 0) {
            printf ("  [SUCCESS] Client %d (v6): Lease for \e[1;32m%s\e[0m acquired!\n", client->client_index, client->leased_ipv6);
            client->state_v6 = STATE_DONE;
        } else {
            fprintf (stderr, "  [FAIL] Client %d (v6): Server replied but offered no address.\n", client->client_index);
            client->state_v6 = STATE_FAILED;
        }
    } else if (dhcp->msg_type == 9) { // DECLINE
        fprintf (stderr, "  [FAIL] Client %d (v6): Received DECLINE.\n", client->client_index);
        client->state_v6 = STATE_FAILED;
    } else if (dhcp->msg_type == 10) { // RECONFIGURE
        // Handle if necessary, for this simulation, consider it a failure for now
        fprintf (stderr, "  [FAIL] Client %d (v6): Received RECONFIGURE.\n", client->client_index);
        client->state_v6 = STATE_FAILED;
    } else if (dhcp->msg_type == 11) { // INFORMATION-REQUEST
        // Not expected in client flow
        fprintf (stderr, "  [FAIL] Client %d (v6): Received unexpected INFORMATION-REQUEST.\n", client->client_index);
        client->state_v6 = STATE_FAILED;
    }
}

// --- Socket and Packet Logic ---

static int create_and_bind_udp_socket (const char *if_name, int *if_index_out)
{
    int sock_fd = socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd < 0) {
        perror ("socket(AF_INET6)");
        return -1;
    }

    int reuse = 1;
    if (setsockopt (sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof (reuse)) < 0) {
        perror ("setsockopt(SO_REUSEADDR)"); close (sock_fd); return -1;
    }
    // Bind the socket to a specific interface to control where packets are sent/received
    if (setsockopt (sock_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen (if_name)) < 0) {
        perror ("setsockopt(SO_BINDTODEVICE)"); close (sock_fd); return -1;
    }

    struct ifreq ifr;
    strncpy (ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl (sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror ("ioctl(SIOCGIFINDEX)");
        close (sock_fd);
        return -1;
    }
    *if_index_out = ifr.ifr_ifindex;

    // Join the All_DHCP_Servers_and_Relay_Agents multicast group (ff02::1:2)
    // This ensures the client socket explicitly listens for server multicast replies.
    struct ipv6_mreq mreq;
    inet_pton (AF_INET6, "ff02::1:2", &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = *if_index_out; // Use interface index
    if (setsockopt (sock_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof (mreq)) < 0) {
        perror ("setsockopt(IPV6_JOIN_GROUP)");
        close (sock_fd);
        return -1;
    }

    struct sockaddr_in6 client_addr = {0};
    client_addr.sin6_family = AF_INET6;
    client_addr.sin6_addr = in6addr_any; // Bind to any local address on the specified interface
    client_addr.sin6_port = htons (DHCP_CLIENT_PORT_V6); // DHCPv6 client port is 546
    if (bind (sock_fd, (struct sockaddr *) &client_addr, sizeof (client_addr)) < 0) {
        perror ("bind to UDP port 546"); close (sock_fd); return -1;
    }
    return sock_fd;
}

static int build_and_send_v6_packet (int sock_fd, int if_index, simulated_client *client, uint8_t msg_type)
{
    uint8_t buffer[1514]; memset (buffer, 0, sizeof (buffer));
    dhcp_packet_v6 *dhcp = (dhcp_packet_v6 *) buffer;

    dhcp->msg_type = msg_type;
    // Transaction ID (XID) - 3 bytes
    dhcp->xid[0] = (client->xid_v6 >> 16) & 0xFF;
    dhcp->xid[1] = (client->xid_v6 >> 8) & 0xFF;
    dhcp->xid[2] = client->xid_v6 & 0xFF;

    uint8_t *opt_ptr = (uint8_t *) (dhcp + 1);

    // Option 1: Client Identifier (DUID)
    // DUID-LL (Link-Layer Address) type: {0x00, 0x03, 0x00, 0x01} (type, hw_type)
    // Followed by 6-byte MAC address
    uint8_t duid_data[10] = {0x00, 0x03, 0x00, 0x01}; // DUID-LL (type 3), HW type Ethernet (type 1)
    memcpy (duid_data + 4, client->mac_addr, 6); // Append MAC address
    opt_ptr = add_dhcp_option_v6 (opt_ptr, 1, sizeof (duid_data), duid_data);

    // Option 16: Vendor Class (REQUIRED for Kea classification)
    // Format: 4 bytes for Enterprise-ID + VCI string
    uint32_t enterprise_id_val = 0; // Using 0 as a generic Enterprise ID for this simulation
    size_t vci_len = strlen (client->vci);
    uint8_t vendor_class_data[4 + vci_len];
    memcpy (vendor_class_data, &enterprise_id_val, 4); // Enterprise-ID
    memcpy (vendor_class_data + 4, client->vci, vci_len); // VCI string
    opt_ptr = add_dhcp_option_v6 (opt_ptr, 16, sizeof (vendor_class_data), vendor_class_data);

    // Option 2: Server Identifier (DUID) - only included in REQUEST
    if (msg_type == 3 && client->server_duid_len_v6 > 0) {
        opt_ptr = add_dhcp_option_v6 (opt_ptr, 2, client->server_duid_len_v6, client->server_duid_v6);
    }

    // Option 3: Identity Association for Non-temporary Address (IA_NA)
    uint32_t iaid = htonl (client->client_index); // IAID for this client (can be arbitrary unique ID)
    uint32_t t1 = 0, t2 = 0; // T1 and T2 lifetimes (default to 0 for initial messages or if not specified)

    // Prepare inner options for IA_NA
    uint8_t iana_inner_options_buffer[256]; // Buffer for sub-options
    uint8_t *iana_inner_opt_ptr = iana_inner_options_buffer;

    // If this is a REQUEST (type 3), and we received an offered address (IA_ADDR) in ADVERTISE, include it
    if (msg_type == 3 && strlen (client->leased_ipv6) > 0) {
        // Option 5: IA Address (IA_ADDR) - sub-option of IA_NA
        // Format: IPv6 address (16 bytes) + preferred lifetime (4 bytes) + valid lifetime (4 bytes)
        uint8_t ia_addr_data[16 + 4 + 4];
        struct in6_addr offered_ipv6_addr;
        inet_pton (AF_INET6, client->leased_ipv6, &offered_ipv6_addr);
        memcpy (ia_addr_data, &offered_ipv6_addr, 16);

        // Use default/example lifetimes if not provided by server in ADVERTISE
        uint32_t preferred_lifetime = htonl (7200); // Example: 2 hours
        uint32_t valid_lifetime = htonl (7200);   // Example: 2 hours
        memcpy (ia_addr_data + 16, &preferred_lifetime, 4);
        memcpy (ia_addr_data + 20, &valid_lifetime, 4);

        iana_inner_opt_ptr = add_dhcp_option_v6 (iana_inner_opt_ptr, 5, sizeof (ia_addr_data), ia_addr_data);
    }

    // Construct the full IA_NA payload: IAID (4), T1 (4), T2 (4), then inner options
    size_t iana_inner_options_len = iana_inner_opt_ptr - iana_inner_options_buffer;
    uint8_t iana_full_payload[12 + iana_inner_options_len];
    memcpy (iana_full_payload, &iaid, 4);
    memcpy (iana_full_payload + 4, &t1, 4);
    memcpy (iana_full_payload + 8, &t2, 4);
    if (iana_inner_options_len > 0) { // Only copy if there are inner options
        memcpy (iana_full_payload + 12, iana_inner_options_buffer, iana_inner_options_len);
    }

    opt_ptr = add_dhcp_option_v6 (opt_ptr, 3, sizeof (iana_full_payload), iana_full_payload);

    // Option 6: Elapsed Time (common, but not strictly needed for this simulation)
    // Option 23: Preference (for Solicit, not needed)
    // Option 24: Reconfigure Accept (for Solicit, not needed)
    // Option 25: Unicast (for Solicit, not needed)
    // Option 39: Status Code (for Solicit, not needed)
    // Option 82: Solicit Max RT (for Solicit, not needed)

    ssize_t dhcp_len = opt_ptr - (uint8_t *) dhcp;

    // Destination for DHCPv6 messages: All_DHCP_Servers_and_Relay_Agents multicast address (ff02::1:2)
    struct sockaddr_in6 dest_addr = {0};
    dest_addr.sin6_family = AF_INET6;
    dest_addr.sin6_port = htons (DHCP_SERVER_PORT_V6);
    dest_addr.sin6_scope_id = if_index; // Critical for link-local multicast addresses
    inet_pton (AF_INET6, "ff02::1:2", &dest_addr.sin6_addr);

    if (sendto (sock_fd, buffer, dhcp_len, 0, (struct sockaddr *) &dest_addr, sizeof (dest_addr)) < 0) {
        perror ("sendto DHCPv6"); return -1;
    }
    return 0;
}

static uint8_t *add_dhcp_option_v6 (uint8_t *opt, uint16_t code, uint16_t len, const void *data)
{
    dhcp_option_v6 *option = (dhcp_option_v6 *) opt;
    option->code = htons (code);
    option->len = htons (len);
    if (data && len > 0) {
        memcpy (option + 1, data, len);
    }
    return (uint8_t *) (option + 1) + len;
}

static void parse_dhcp_reply_v6 (const uint8_t *options, ssize_t options_len, simulated_client *client)
{
    const uint8_t *opt_ptr = options;
    const uint8_t *end = options + options_len;
    while (opt_ptr < end) {
        if (opt_ptr + sizeof (dhcp_option_v6) > end) { // Check if there's enough space for option header
            break;
        }
        const dhcp_option_v6 *opt = (const dhcp_option_v6 *) opt_ptr;
        uint16_t code = ntohs (opt->code);
        uint16_t opt_len = ntohs (opt->len);
        const uint8_t *opt_data = (const uint8_t *) (opt + 1);

        if (opt_data + opt_len > end) { // Check if option data extends beyond packet end
            break;
        }

        if (code == 2) { // Server DUID (Option 2)
            if (opt_len <= sizeof (client->server_duid_v6)) { // Ensure buffer won't overflow
                memcpy (client->server_duid_v6, opt_data, opt_len);
                client->server_duid_len_v6 = opt_len;
            } else {
                fprintf (stderr, "Warning: Server DUID too long (%d bytes) for buffer.\n", opt_len);
            }
        } else if (code == 3) { // Identity Association for Non-temporary Address (IA_NA - Option 3)
            // IA_NA contains IAID (4 bytes), T1 (4 bytes), T2 (4 bytes), followed by sub-options
            if (opt_len < 12) { // Minimum length for IA_NA is 12 (IAID, T1, T2)
                fprintf (stderr, "Warning: IA_NA option too short (%d bytes).\n", opt_len);
                opt_ptr += sizeof (dhcp_option_v6) + opt_len; // Skip this malformed option
                continue;
            }

            // Skip IAID, T1, T2 to parse sub-options
            const uint8_t *ia_sub_ptr = opt_data + 12;
            const uint8_t *ia_sub_end = opt_data + opt_len;

            while (ia_sub_ptr < ia_sub_end) {
                if (ia_sub_ptr + sizeof (dhcp_option_v6) > ia_sub_end) {
                    break; // Not enough space for sub-option header
                }
                const dhcp_option_v6 *ia_sub_opt = (const dhcp_option_v6 *) ia_sub_ptr;
                uint16_t ia_sub_code = ntohs (ia_sub_opt->code);
                uint16_t ia_sub_len = ntohs (ia_sub_opt->len);
                const uint8_t *ia_sub_data = (const uint8_t *) (ia_sub_opt + 1);

                if (ia_sub_data + ia_sub_len > ia_sub_end) {
                    break; // Sub-option data extends beyond IA_NA option
                }

                if (ia_sub_code == 5 && ia_sub_len >= 16) { // IA Address (IA_ADDR - Option 5)
                    // IA_ADDR contains IPv6 address (16 bytes) + preferred lifetime (4) + valid lifetime (4)
                    // We only need the address here.
                    inet_ntop (AF_INET6, (const void *) (ia_sub_data), client->leased_ipv6, sizeof (client->leased_ipv6));
                }
                ia_sub_ptr += sizeof (dhcp_option_v6) + ia_sub_len;
            }
        }
        opt_ptr += sizeof (dhcp_option_v6) + opt_len;
    }
}

static long long get_current_time_ms_v6()
{
    struct timespec spec; clock_gettime (CLOCK_MONOTONIC, &spec);
    return (long long) spec.tv_sec * 1000 + (long long) spec.tv_nsec / 1000000;
}