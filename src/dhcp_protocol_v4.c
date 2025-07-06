/**
 * @file dhcp_protocol_v4.c
 * @brief Contains all logic for DHCPv4 packet crafting and state machine.
 */

#include "dhcp_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#pragma pack(push, 1)
typedef struct {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16], sname[64], file[128];
    uint32_t magic_cookie;
    uint8_t options[312];
} dhcp_packet_v4;
#pragma pack(pop)

// Internal helpers for this file
static long long get_current_time_ms_v4();
static uint16_t calculate_checksum_v4 (void *vdata, size_t length);
static uint8_t *add_dhcp_option_v4 (uint8_t *opt, uint8_t code, uint8_t len, const void *data);
static int build_and_send_v4_packet (int sock_fd, int if_index, simulated_client *client, uint8_t msg_type);
static uint8_t get_dhcp_message_type_v4 (const dhcp_packet_v4 *packet);
static void parse_dhcp_offer_v4 (const dhcp_packet_v4 *packet, uint32_t *server_id);

// --- Public API Function ---

int perform_concurrent_dhcpv4 (const char *if_name, simulated_client *clients, int num_clients)
{
    printf ("\n\e[1m[+] Starting concurrent DHCPv4 simulation for %d clients on %s...\e[0m\n", num_clients, if_name);
    for (int i = 0; i < num_clients; i++) {
        clients[i].state_v4 = STATE_INIT;
        clients[i].xid_v4 = rand();
        clients[i].last_sent_time_v4_ms = 0;
    }
    int success_count = run_simulation_loop (if_name, clients, num_clients, 4);
    printf ("[+] DHCPv4 simulation finished. \e[1;32m%d\e[0m/\e[1m%d\e[0m clients succeeded.\n", success_count, num_clients);
    return success_count;
}

// --- Internal Handlers ---

void handle_dhcpv4_action (int sock_fd, int if_index, simulated_client *client)
{
    long long now = get_current_time_ms_v4();
    if (client->state_v4 != STATE_DONE && client->state_v4 != STATE_FAILED) {
        if (client->state_v4 == STATE_INIT || (client->state_v4 == STATE_V4_DISCOVER_SENT &&
                                        now - client->last_sent_time_v4_ms > DHCP_V4_RETRY_MS)) {
            if (client->state_v4 == STATE_V4_DISCOVER_SENT) {
                printf ("  [RETRY] Client %d (v4) DISCOVER\n", client->client_index);
            }
            build_and_send_v4_packet (sock_fd, if_index, client, 1); // DISCOVER
            client->state_v4 = STATE_V4_DISCOVER_SENT;
            client->last_sent_time_v4_ms = now;
        }
    }
}

void handle_dhcpv4_reply (const uint8_t *buffer, ssize_t len, simulated_client *client, int sock_fd, int if_index)
{
    const struct iphdr *ip = (const struct iphdr *) (buffer + sizeof (struct ethhdr));
    const struct udphdr *udp = (const struct udphdr *) ( (const uint8_t *) ip + (ip->ihl * 4));
    const dhcp_packet_v4 *dhcp = (const dhcp_packet_v4 *) (udp + 1);

    if (client->xid_v4 != ntohl (dhcp->xid)) {
        return;
    }
    if (client->state_v4 >= STATE_DONE) {
        return;
    }

    uint8_t msg_type = get_dhcp_message_type_v4 (dhcp);
    if (client->state_v4 == STATE_V4_DISCOVER_SENT && msg_type == 2) { // OFFER
        printf ("  [RX] Client %d (v4): Received OFFER\n", client->client_index);
        parse_dhcp_offer_v4 (dhcp, &client->server_id_v4);
        client->offered_ip_v4 = dhcp->yiaddr;
        printf ("  [ACTION] Client %d (v4): Sending REQUEST\n", client->client_index);
        build_and_send_v4_packet (sock_fd, if_index, client, 3); // REQUEST
        client->state_v4 = STATE_V4_REQUEST_SENT;
        client->last_sent_time_v4_ms = get_current_time_ms_v4();
    } else if (client->state_v4 == STATE_V4_REQUEST_SENT && msg_type == 5) { // ACK
        struct in_addr leased_addr = {.s_addr = dhcp->yiaddr};
        inet_ntop (AF_INET, &leased_addr, client->leased_ipv4, sizeof (client->leased_ipv4));
        printf ("  [SUCCESS] Client %d (v4): Lease for \e[1;32m%s\e[0m acquired!\n", client->client_index, client->leased_ipv4);
        client->state_v4 = STATE_DONE;
    } else if (msg_type == 6) { // NAK
        fprintf (stderr, "  [FAIL] Client %d (v4): Received NAK.\n", client->client_index);
        client->state_v4 = STATE_FAILED;
    }
}


// --- Packet Building and Parsing ---

static int build_and_send_v4_packet (int sock_fd, int if_index, simulated_client *client, uint8_t msg_type)
{
    uint8_t buffer[1514]; memset (buffer, 0, sizeof (buffer));
    struct ethhdr *eth = (struct ethhdr *) buffer;
    struct iphdr *ip = (struct iphdr *) (eth + 1);
    struct udphdr *udp = (struct udphdr *) ( (uint8_t *) ip + sizeof (struct iphdr));
    dhcp_packet_v4 *dhcp = (dhcp_packet_v4 *) (udp + 1);

    dhcp->op = 1; dhcp->htype = 1; dhcp->hlen = 6; dhcp->xid = htonl (client->xid_v4);
    dhcp->flags = htons (0x8000); memcpy (dhcp->chaddr, client->mac_addr, 6);
    dhcp->magic_cookie = htonl (0x63825363);

    uint8_t *opt_ptr = dhcp->options;
    opt_ptr = add_dhcp_option_v4 (opt_ptr, 53, 1, &msg_type);
    opt_ptr = add_dhcp_option_v4 (opt_ptr, 60, strlen (client->vci), client->vci);

    if (msg_type == 3) { // REQUEST
        opt_ptr = add_dhcp_option_v4 (opt_ptr, 50, 4, &client->offered_ip_v4);
        opt_ptr = add_dhcp_option_v4 (opt_ptr, 54, 4, &client->server_id_v4);
    }
    *opt_ptr++ = 255;

    ssize_t dhcp_len = opt_ptr - (uint8_t *) dhcp;
    ssize_t udp_len = sizeof (struct udphdr) + dhcp_len;
    ssize_t ip_len = sizeof (struct iphdr) + udp_len;

    udp->source = htons (DHCP_CLIENT_PORT_V4); udp->dest = htons (DHCP_SERVER_PORT_V4);
    udp->len = htons (udp_len); udp->check = 0;
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons (ip_len); ip->ttl = 64;
    ip->protocol = IPPROTO_UDP; ip->saddr = 0; ip->daddr = 0xFFFFFFFF;
    ip->check = 0; ip->check = calculate_checksum_v4 (ip, sizeof (struct iphdr));

    memset (eth->h_dest, 0xff, 6); memcpy (eth->h_source, client->mac_addr, 6);
    eth->h_proto = htons (ETH_P_IP);

    struct sockaddr_ll dest_addr = { .sll_family = AF_PACKET, .sll_ifindex = if_index, .sll_halen = ETH_ALEN };
    memcpy (dest_addr.sll_addr, eth->h_dest, ETH_ALEN);
    if (sendto (sock_fd, buffer, sizeof (struct ethhdr) + ip_len, 0, (struct sockaddr *) &dest_addr, sizeof (dest_addr)) < 0) {
        perror ("sendto v4"); return -1;
    }
    return 0;
}

static uint8_t *add_dhcp_option_v4 (uint8_t *opt, uint8_t code, uint8_t len, const void *data)
{
    *opt++ = code; *opt++ = len; memcpy (opt, data, len); return opt + len;
}

static uint8_t get_dhcp_message_type_v4 (const dhcp_packet_v4 *packet)
{
    const uint8_t *options = packet->options;
    const uint8_t *end = (const uint8_t *) packet + 312;
    while (options < end && *options != 255) {
        if (*options == 0) {
            options++;
            continue;
        }
        if (*options == 53) {
            return options[2];
        }
        options += options[1] + 2;
    }
    return 0;
}

static void parse_dhcp_offer_v4 (const dhcp_packet_v4 *packet, uint32_t *server_id)
{
    const uint8_t *options = packet->options;
    const uint8_t *end = (const uint8_t *) packet + 312;
    while (options < end && *options != 255) {
        if (*options == 0) {
            options++;
            continue;
        }
        if (*options == 54) {
            memcpy (server_id, &options[2], 4);
            return;
        }
        options += options[1] + 2;
    }
}

static uint16_t calculate_checksum_v4 (void *vdata, size_t length)
{
    char *data = vdata; uint32_t acc = 0;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy (&word, data + i, 2);
        acc += ntohs (word);
    }
    if (length & 1) {
        uint8_t byte = data[length - 1];
        acc += byte << 8;
    }
    while (acc >> 16) {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    return htons (~acc);
}

static long long get_current_time_ms_v4()
{
    struct timespec spec; clock_gettime (CLOCK_MONOTONIC, &spec);
    return (long long) spec.tv_sec * 1000 + (long long) spec.tv_nsec / 1000000;
}