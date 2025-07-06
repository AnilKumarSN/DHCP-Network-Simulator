/**
 * @file dhcp_client.c
 * @brief High-level dispatcher for DHCP simulations.
 */
#include "dhcp_crafter.h"
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
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h> // Required for BPF_STMT, BPF_JUMP, etc.
#include <netinet/ip.h>   // Required for iphdr
#include <netinet/udp.h>  // Required for udphdr
#include <ifaddrs.h>

static int create_and_bind_raw_socket (const char *if_name, int *if_index_out, struct in6_addr *ll_addr);
static int setup_epoll (int sock_fd);
static void dispatch_incoming_packet (uint8_t *buffer, ssize_t len, simulated_client *clients, int num_clients, int sock_fd, int if_index,
                const struct in6_addr *ll_addr);

// This is now the ONLY function in this file. It is called by the public API functions.
int run_simulation_loop (const char *if_name, simulated_client *clients, int num_clients, int protocol)
{
    int sock_fd = -1, epoll_fd = -1, if_index = 0;
    struct in6_addr ll_addr = {0};
    if ( (sock_fd = create_and_bind_raw_socket (if_name, &if_index, &ll_addr)) < 0) {
        return -1;
    }
    if ( (epoll_fd = setup_epoll (sock_fd)) < 0) {
        close (sock_fd);
        return -1;
    }

    long long start_time = time (NULL);
    int completed_clients = 0;

    // Use the now-defined macros
    while (completed_clients < num_clients && time (NULL) - start_time < DHCP_GLOBAL_TIMEOUT_S) {
        for (int i = 0; i < num_clients; i++) {
            if (protocol == 4) {
                handle_dhcpv4_action (sock_fd, if_index, &clients[i]);
            } else {
                handle_dhcpv6_action (sock_fd, if_index, &clients[i], &ll_addr);
            }
        }

        struct epoll_event events[MAX_EPOLL_EVENTS]; // Use the now-defined macro
        int num_events = epoll_wait (epoll_fd, events, MAX_EPOLL_EVENTS, 200); // Use the now-defined macro
        for (int i = 0; i < num_events; i++) {
            uint8_t buffer[2048];
            ssize_t len = recv (sock_fd, buffer, sizeof (buffer), 0);
            if (len > 0) {
                dispatch_incoming_packet (buffer, len, clients, num_clients, sock_fd, if_index, &ll_addr);
            }
        }

        completed_clients = 0;
        for (int i = 0; i < num_clients; i++) {
            if (protocol == 4 && clients[i].state_v4 >= STATE_DONE) {
                completed_clients++;
            }
            if (protocol == 6 && clients[i].state_v6 >= STATE_DONE) {
                completed_clients++;
            }
        }
    }

    close (sock_fd); close (epoll_fd);

    int successful_clients = 0;
    for (int i = 0; i < num_clients; i++) {
        if (protocol == 4 && clients[i].state_v4 == STATE_DONE) {
            successful_clients++;
        }
        if (protocol == 6 && clients[i].state_v6 == STATE_DONE) {
            successful_clients++;
        }
    }
    return successful_clients;
}

static int create_and_bind_raw_socket (const char *if_name, int *if_index_out, struct in6_addr *ll_addr)
{
    int sock_fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if (sock_fd < 0) {
        perror ("socket(AF_PACKET)");
        return -1;
    }

    // Improved BPF filter as suggested:
    // This filter targets IPv4 UDP packets on ports 67 (server) or 68 (client).
    // It's more specific than the previous one that accepted all packets.
    struct sock_filter dhcp_filter[] = {
        // Load EtherType (offset 12 in Ethernet frame)
        BPF_STMT (BPF_LD | BPF_H | BPF_ABS, offsetof (struct ethhdr, h_proto)),
        // Check for IPv4 (0x0800)
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 6), // if proto != IP, jump to reject
        // Load IP protocol (offset 23 in IP header)
        BPF_STMT (BPF_LD | BPF_B | BPF_ABS, sizeof (struct ethhdr) + offsetof (struct iphdr, protocol)),
        // Check for UDP (17)
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 4), // if proto != UDP, jump to reject
        // Load UDP dest port (offset 36 from start of Ethernet frame, or 16 from start of UDP header)
        BPF_STMT (BPF_LD | BPF_H | BPF_ABS, sizeof (struct ethhdr) + sizeof (struct iphdr) + offsetof (struct udphdr, dest)),
        // Check for DHCP server port (67) or client port (68)
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, DHCP_SERVER_PORT_V4, 2, 0), // if dest_port == 67, jump to accept
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, DHCP_CLIENT_PORT_V4, 1, 0), // if dest_port == 68, jump to accept
        // Reject packet (return 0)
        BPF_STMT (BPF_RET | BPF_K, 0),
        // Accept packet (return max length to capture)
        BPF_STMT (BPF_RET | BPF_K, 0xFFFFFFFF), // Use 0xFFFFFFFF for full snaplen
    };
    struct sock_fprog bpf = { .len = sizeof (dhcp_filter) / sizeof (dhcp_filter[0]), .filter = dhcp_filter };

    if (setsockopt (sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof (bpf)) < 0) {
        fprintf (stderr, "setsockopt(SO_ATTACH_FILTER): %s\n", strerror (errno));
        close (sock_fd); return -1;
    }

    struct ifreq ifr;
    strncpy (ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl (sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror ("ioctl(SIOCGIFINDEX)");
        close (sock_fd);
        return -1;
    }
    *if_index_out = ifr.ifr_ifindex;

    // This part is for getting link-local IPv6 addr for raw sockets in original design.
    // For DHCPv4 only (via run_simulation_loop(..., 4)), ll_addr is not actually used by action/reply.
    // However, keeping it here as dhcp_client.c is a general dispatcher.
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs (&ifaddr) == -1) {
        perror ("getifaddrs");
        close (sock_fd);
        return -1;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET6 && strcmp (ifa->ifa_name, if_name) == 0) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *) ifa->ifa_addr;
            if (IN6_IS_ADDR_LINKLOCAL (&sa->sin6_addr)) {
                memcpy (ll_addr, &sa->sin6_addr, sizeof (struct in6_addr));
                break;
            }
        }
    }
    freeifaddrs (ifaddr);

    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_ifindex = *if_index_out, .sll_protocol = htons (ETH_P_ALL) };
    if (bind (sock_fd, (struct sockaddr *) &sll, sizeof (sll)) < 0) {
        perror ("bind");
        close (sock_fd);
        return -1;
    }
    return sock_fd;
}

static void dispatch_incoming_packet (uint8_t *buffer, ssize_t len, simulated_client *clients, int num_clients, int sock_fd, int if_index,
                const struct in6_addr *ll_addr)
{
    struct ethhdr *eth = (struct ethhdr *) buffer;
    for (int i = 0; i < num_clients; i++) {
        // Ignore self-sent packets (though BPF filter helps reduce this for DHCPv4)
        if (memcmp (eth->h_source, clients[i].mac_addr, ETH_ALEN) == 0) {
            return;
        }
    }

    for (int i = 0; i < num_clients; i++) {
        // Broadacst (FF:FF:FF:FF:FF:FF), IPv6 Multicast (33:33:xx:xx:xx:xx), or unicast to client's MAC
        // The BPF filter helps for IPv4, but this check remains important for general dispatch and IPv6 unicast.
        if ( (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff) || (eth->h_dest[0] == 0x33 && eth->h_dest[1] == 0x33) ||
                        (memcmp (eth->h_dest, clients[i].mac_addr, ETH_ALEN) == 0)) {
            if (ntohs (eth->h_proto) == ETH_P_IP) {
                // For DHCPv4, ensure the packet is long enough to contain an IP and UDP header before casting
                if (len < sizeof (struct ethhdr) + sizeof (struct iphdr) + sizeof (struct udphdr)) {
                    continue;
                }
                // Further checks for correct ports are done within handle_dhcpv4_reply if needed,
                // but the BPF filter should primarily handle this now.
                handle_dhcpv4_reply (buffer, len, &clients[i], sock_fd, if_index);
            } else if (ntohs (eth->h_proto) == ETH_P_IPV6) {
                // For DHCPv6, the packet is expected to be received via the AF_INET6 UDP socket,
                // so this path is technically not used for DHCPv6 traffic.
                // However, if raw sockets were used for DHCPv6 reception for some reason,
                // this would be the dispatch point. Keeping it for completeness/future.
                // handle_dhcpv6_reply(buffer, len, &clients[i], sock_fd, if_index, ll_addr); // This function is called differently in dhcp_protocol_v6.c
            }
        }
    }
}

static int setup_epoll (int sock_fd)
{
    int epoll_fd;
    if ( (epoll_fd = epoll_create1 (0)) < 0) {
        perror ("epoll_create1");
        return -1;
    }
    struct epoll_event event = {.data.fd = sock_fd, .events = EPOLLIN};
    if (epoll_ctl (epoll_fd, EPOLL_CTL_ADD, sock_fd, &event) < 0) {
        perror ("epoll_ctl");
        close (epoll_fd);
        return -1;
    }
    return epoll_fd;
}