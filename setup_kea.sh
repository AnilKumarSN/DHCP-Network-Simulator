#!/bin/bash

# --- Configuration ---
KEE_CONFIG_PATH="/etc/kea"
BACKUP_BASE_DIR="/var/backups"
# List of Kea packages to install for version 3.0.0
KEE_PACKAGES_TO_INSTALL="isc-kea-dhcp4-server isc-kea-dhcp6-server isc-kea-ctrl-agent isc-kea-common isc-kea-admin isc-kea-perfdhcp"
KEA_REPO_SETUP_SCRIPT="https://dl.cloudsmith.io/public/isc/kea-3-0/setup.deb.sh"

# --- Functions for Logging ---
log_info() {
    echo -e "\n\033[0;32mINFO:\033[0m $1"
}

log_warn() {
    echo -e "\n\033[0;33mWARN:\033[0m $1" >&2
}

log_error() {
    echo -e "\n\033[0;31mERROR:\033[0m $1" >&2
    exit 1
}

# --- Pre-requisites Check ---
check_prerequisites() {
    log_info "Checking for required commands..."
    for cmd in apt curl systemctl find; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "$cmd is not installed. Please install it and try again."
        fi
    done
}

# --- Main Script ---

# Ensure the script is run as root
if [[ "$EUID" -ne 0 ]]; then
    log_error "This script must be run as root (or with sudo)."
fi

log_info "Starting ISC Kea DHCP uninstallation and 3.0.0 installation process."

check_prerequisites

# 1. Stop all running Kea services
log_info "Stopping all running Kea services..."
# Identify active services whose names contain 'kea'
KEASERVICES=$(systemctl list-units --type=service --state=running 2>/dev/null | grep 'kea' | awk '{print $1}')
if [[ -n "$KEASERVICES" ]]; then
    echo "$KEASERVICES" | while read -r service; do
        log_info "Attempting to stop $service..."
        systemctl stop "$service" || log_warn "Failed to stop $service. This might indicate it wasn't running or an issue occurred. Continuing..."
    done
else
    log_info "No active Kea services found to stop."
fi

# 2. Backup existing Kea configuration
TIMESTAMP=$(date +%Y%m%d%H%M%S)
BACKUP_DIR="${BACKUP_BASE_DIR}/kea_config_backup_${TIMESTAMP}"

log_info "Backing up existing Kea configuration from '$KEE_CONFIG_PATH' to '$BACKUP_DIR'..."
if [ -d "$KEE_CONFIG_PATH" ]; then
    mkdir -p "$BACKUP_DIR" || log_error "Failed to create backup directory '$BACKUP_DIR'."
    cp -r "$KEE_CONFIG_PATH" "$BACKUP_DIR/"
    log_info "Kea configuration successfully backed up to '$BACKUP_DIR'."
else
    log_warn "Kea configuration directory '$KEE_CONFIG_PATH' not found. No configuration to back up."
fi

# 3. Purge existing Kea packages systematically
log_info "Identifying existing ISC Kea packages using 'apt list --installed | grep kea'..."
# apt list --installed provides output like: kea-common/focal,now 2.0.0-1ubuntu20.04.1 amd64 [installed]
# We need to extract just the package name (e.g., kea-common)
KEAPACKAGES=$(apt list --installed 2>/dev/null | grep 'kea' | awk -F'/' '{print $1}')

if [[ -n "$KEAPACKAGES" ]]; then
    log_info "Found Kea packages to purge: $KEAPACKAGES"
    # Use 'apt-get -y purge' to remove packages and their configuration files
    log_info "Attempting to purge existing Kea packages..."
    if ! apt-get -y purge $KEAPACKAGES; then
        log_warn "Some Kea packages might not have been fully purged. Please review the output above for errors. Continuing with installation."
    else
        log_info "Existing Kea packages purged successfully."
    fi
else
    log_info "No existing Kea packages found to purge."
fi

# 4. Remove old Kea repository configurations
log_info "Removing old Kea apt repository configurations from /etc/apt/sources.list.d/..."
find /etc/apt/sources.list.d/ -name "*kea*.list" -delete
log_info "Old Kea repository files removed (if any)."

# Refresh apt package list after removing old repos
apt-get update || log_warn "Failed to update apt package list after removing old repositories. This might cause issues."

# 5. Add the new ISC Kea 3.0.0 repository
log_info "Adding ISC Kea 3.0.0 repository using Cloudsmith setup script..."
if ! curl -1sLf "$KEA_REPO_SETUP_SCRIPT" | bash; then
    log_error "Failed to add ISC Kea 3.0.0 repository. Please check your internet connection or the Cloudsmith URL."
fi
log_info "ISC Kea 3.0.0 repository added successfully."

# 6. Update package lists again after adding the new repository
log_info "Updating apt package lists after adding new repository..."
apt-get update || log_error "Failed to update apt package lists after adding the new repository."

# 7. Install ISC Kea 3.0.0 packages
log_info "Installing ISC Kea 3.0.0 packages: $KEE_PACKAGES_TO_INSTALL..."
if ! apt-get -y install $KEE_PACKAGES_TO_INSTALL; then
    log_error "Failed to install ISC Kea 3.0.0 packages. Please check the error messages above."
fi
log_info "ISC Kea 3.0.0 packages installed successfully."

# 8. Verify the installed Kea version
log_info "Verifying Kea 3.0.0 installation..."
INSTALLED_KEA_VERSION=$(kea-dhcp4 -V 2>&1 | grep "Kea version" | awk '{print $3}')
if [[ "$INSTALLED_KEA_VERSION" == "3.0.0" ]]; then
    log_info "Verification successful! ISC Kea version $INSTALLED_KEA_VERSION is installed."
else
    log_warn "Kea version verification failed or returned unexpected version: '$INSTALLED_KEA_VERSION'. Expected '3.0.0'. Manual verification recommended."
fi

log_info "ISC Kea uninstallation and 3.0.0 installation process complete."

# --- Post-installation Instructions ---
echo ""
echo "========================================================================"
echo "                           POST-INSTALLATION STEPS                      "
echo "========================================================================"
echo "Your previous Kea configuration has been backed up to: \033[0;36m$BACKUP_DIR\033[0m"
echo ""
echo "1. \033[1mMigrate Your Configuration:\033[0m"
echo "   You will need to manually copy and adapt your configuration files"
echo "   from '$BACKUP_DIR/kea/' to '/etc/kea/'."
echo "   Be aware that configuration file formats or options might have"
echo "   changed significantly between Kea versions (especially 1.x to 3.x)."
echo "   Refer to Kea 3.0.0 documentation for configuration specifics."
echo "   A typical approach is to start with the new default /etc/kea files"
echo "   and carefully incorporate your specific settings from the backup."
echo ""
echo "   Example (carefully!):"
echo "   \033[0;35msudo cp -r $BACKUP_DIR/kea/* /etc/kea/\033[0m"
echo ""
echo "2. \033[1mStart Kea Services:\033[0m"
echo "   After migrating and verifying your configuration, start the services:"
echo "   \033[0;35msudo systemctl enable kea-dhcp4-server kea-dhcp6-server kea-ctrl-agent\033[0m"
echo "   \033[0;35msudo systemctl start kea-dhcp4-server kea-dhcp6-server kea-ctrl-agent\033[0m"
echo ""
echo "3. \033[1mCheck Service Status:\033[0m"
echo "   Monitor the logs and service status to ensure Kea is running correctly:"
echo "   \033[0;35msudo systemctl status kea-dhcp4-server\033[0m"
echo "   \033[0;35msudo journalctl -u kea-dhcp4-server -f\033[0m"
echo "========================================================================"
echo ""

exit 0
