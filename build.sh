#!/bin/bash
#
# build.sh - A robust build and run script for the Network Namespace DHCP Simulator.
#
# This script handles cleaning up old environments, tuning kernel parameters for
# high-volume traffic, and provides a clean build and execution process.
#

echo "Validating Config: kea-dhcp4 -t conf/red-kea-dhcp4.conf"
sudo kea-dhcp4 -t conf/red-kea-dhcp4.conf

echo "Validating Config: kea-dhcp4 -t conf/blue-kea-dhcp4.conf"
sudo kea-dhcp4 -t conf/blue-kea-dhcp4.conf

echo "Validating Config: kea-dhcp6 -t conf/red-kea-dhcp6.conf"
sudo kea-dhcp6 -t conf/red-kea-dhcp6.conf

echo "Validating Config: kea-dhcp6 -t conf/blue-kea-dhcp6.conf"
sudo kea-dhcp6 -t conf/blue-kea-dhcp6.conf

set -e # Exit immediately if any command fails.

echo "--- Forcefully cleaning up previous environments ---"
# Use 'ip -all netns del' for a more forceful cleanup. The '|| true' part
# ensures the script doesn't fail if no namespaces exist to be deleted.
sudo ip -all netns del >/dev/null 2>&1 || true
sleep 1
echo "    > Previous network namespaces deleted."

echo ""
echo "--- Tuning kernel parameters for high-volume simulation ---"
# Increase ARP/NDP cache thresholds to prevent the kernel from dropping
# neighbor entries under heavy load from many simulated clients.
sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=2048 >/dev/null
sudo sysctl -w net.ipv6.neigh.default.gc_thresh3=2048 >/dev/null
echo "    > Kernel neighbor table thresholds increased."

echo ""
echo "--- Building the project ---"
# Perform a clean build to ensure no old artifacts are used.
rm -rf build/
mkdir build
cd build/

# Configure and build the project using CMake and Make.
cmake ..
make

echo ""
echo "--- Running the simulation with root privileges ---"
# Run the compiled executable directly with sudo.
# The C program will handle the final cleanup internally.
sudo ./netns_sim

echo ""
echo "Simulation finished."
