# Base image
FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for dhcp_simulator.py and setup_kea.sh
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    curl \
    gnupg \
    ca-certificates \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set up a non-root user and grant sudo privileges (optional, but good practice)
# However, for network namespace manipulation as done by the script, running as root
# or having extensive capabilities is simpler.
# The script itself uses 'sudo' for ip commands. If container runs as root, sudo is not strictly needed
# but the script is written to use it. We can ensure sudo is passwordless for root.
RUN echo "root ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Create a working directory
WORKDIR /app

# Copy the setup script and the simulator script into the image
COPY setup_kea.sh .
COPY dhcp_simulator.py .

# Make setup_kea.sh executable and run it to install Kea
# This script itself uses sudo/apt, so it needs to run as root or with sudo configured.
# Since the Docker build process runs as root by default, this should be fine.
RUN chmod +x setup_kea.sh && ./setup_kea.sh

# Make the simulator script executable (optional, as we call it with python3)
RUN chmod +x dhcp_simulator.py

# Default command to run when the container starts
# Users will append arguments like --num-clients, etc. to the `docker run` command.
ENTRYPOINT ["python3", "dhcp_simulator.py"]

# Example of how to build:
# docker build -t dhcp-simulator .

# Example of how to run (see README.md for more details):
# docker run --rm -it \
#   --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
#   --network=host \
#   -v $(pwd)/my_results:/app/perfdhcp_results \
#   dhcp-simulator \
#   --num-clients 2 --host-iface br0 --dhcpv4-server 192.168.100.1 \
#   --output-dir /app/perfdhcp_results
