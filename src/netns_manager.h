#ifndef NETNS_MANAGER_H
#define NETNS_MANAGER_H

/**
 * @file netns_manager.h
 * @brief Public interface for the network namespace management module.
 */

/**
 * @brief Sets up a complete network namespace environment.
 *
 * Creates a namespace, a veth pair, moves the peer, configures IPs, brings
 * links up, and verifies that the interface is fully operational. This is a
 * blocking, all-in-one setup function.
 *
 * @param ns_name The name for the new network namespace (e.g., "red").
 * @param veth_root The name for the veth peer in the root namespace.
 * @param veth_ns The name for the veth peer inside the new namespace.
 * @param ipv4_ns_1 Primary IPv4 address (CIDR) for the namespace interface.
 * @param ipv6_ns_1 Primary IPv6 address (CIDR) for the namespace interface.
 * @param ipv4_ns_2 Secondary IPv4 address (CIDR), or NULL if not needed.
 * @param ipv6_ns_2 Secondary IPv6 address (CIDR), or NULL if not needed.
 * @return 0 on success, -1 on failure.
 */
int setup_namespace_environment (const char *ns_name, const char *veth_root, const char *veth_ns,
                const char *ipv4_ns_1, const char *ipv6_ns_1,
                const char *ipv4_ns_2, const char *ipv6_ns_2);

/**
 * @brief Deletes a network namespace and its associated resources.
 *
 * This function is idempotent and will not fail if the namespace does not exist.
 *
 * @param ns_name The name of the namespace to delete.
 */
void cleanup_namespace_environment (const char *ns_name);

/**
 * @brief Runs an arbitrary shell command inside a specified network namespace.
 *
 * @param ns_name The namespace in which to execute the command.
 * @param command The shell command string to execute.
 */
void run_command_in_ns (const char *ns_name, const char *command);

#endif // NETNS_MANAGER_H