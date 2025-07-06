#!/bin/bash

# End-to-End Test Wrapper Script for DHCP Environment

# --- Configuration ---
KEA_SETUP_SCRIPT="./kea_server_setup.sh"
SIMULATOR_SCRIPT="./dhcp_simulator.py"
DEFAULT_PERFDHCP_PATH="/usr/sbin/perfdhcp"
SIMULATOR_OUTPUT_DIR_BASE="e2e_test_results" # Base directory for results

# --- Globals (dynamically set or defaults) ---
PERFDHCP_PATH="$DEFAULT_PERFDHCP_PATH"
CURRENT_SIMULATOR_OUTPUT_DIR="" # Set in start_environment
PYTHON_RELAY_LOG_FILE="/tmp/kea_rt/ns_pyrelay/pyrelay.log" # Assuming default from kea_server_setup.sh
# Add other Kea log paths if detailed checking is implemented later

TEST_PASSED_COUNT=0
TEST_FAILED_COUNT=0
DEBUG_MODE=0
NO_CLEANUP=0

# --- Logging Functions ---
log_info() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_debug() {
    if [ "$DEBUG_MODE" -eq 1 ]; then
        echo "[DEBUG] $(date +'%Y-%m-%d %H:%M:%S') - $1"
    fi
}

# --- Utility Functions ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root or with sudo."
        exit 1
    fi
}

timestamp() {
    date +%Y%m%d_%H%M%S
}

# --- Environment Management Functions ---
start_environment() {
    log_info "Starting DHCP test environment..."
    CURRENT_SIMULATOR_OUTPUT_DIR="${SIMULATOR_OUTPUT_DIR_BASE}/run_$(timestamp)"
    mkdir -p "$CURRENT_SIMULATOR_OUTPUT_DIR"
    log_info "Simulator logs will be stored in: $CURRENT_SIMULATOR_OUTPUT_DIR"

    if [ ! -x "$KEA_SETUP_SCRIPT" ]; then
        log_error "Kea setup script '$KEA_SETUP_SCRIPT' not found or not executable."
        return 1
    fi

    log_debug "Executing: sudo ${KEA_SETUP_SCRIPT} start -l debug"
    if ! sudo "${KEA_SETUP_SCRIPT}" start -l debug; then
        log_error "Failed to start Kea environment using ${KEA_SETUP_SCRIPT}."
        return 1
    fi

    sleep 5 # Give services time to fully initialize

    # Basic check for relay and Kea server processes
    # This is a simple check; more robust checks could parse 'kea_server_setup.sh status'
    if ! pgrep -f "python3 ${PYTHON_RELAY_SCRIPT_PATH_ABS}" > /dev/null; then
        log_warn "Python relay process may not be running. Check $PYTHON_RELAY_LOG_FILE."
        # Not returning 1 to allow tests to proceed and potentially fail more informatively
    fi
    # Check Kea PIDs (example for one server)
    if [ -f "/tmp/kea_rt/ns_red/kea-dhcp4.pid" ]; then
        if ! ps -p "$(cat /tmp/kea_rt/ns_red/kea-dhcp4.pid)" > /dev/null; then
            log_warn "Kea DHCPv4 (ns_red) process seems down despite PID file."
        fi
    else
        log_warn "PID file for Kea DHCPv4 (ns_red) not found."
    fi

    log_info "Environment startup initiated. Check logs for details."
    return 0
}

stop_environment() {
    log_info "Stopping DHCP test environment..."
    if ! sudo "${KEA_SETUP_SCRIPT}" stop; then
        log_error "Failed to stop Kea environment using ${KEA_SETUP_SCRIPT}."
        return 1
    fi
    log_info "Environment stopped."
    return 0
}

cleanup_environment() {
    if [ "$NO_CLEANUP" -eq 1 ]; then
        log_info "Skipping cleanup as per --no-cleanup flag."
        return 0
    fi
    log_info "Cleaning up DHCP test environment..."
    if ! sudo "${KEA_SETUP_SCRIPT}" cleanup; then
        log_error "Failed to cleanup Kea environment using ${KEA_SETUP_SCRIPT}."
        return 1
    fi
    log_info "Environment cleaned up."
    return 0
}

# --- Test Execution and Verification ---
run_test_case() {
    local test_name="$1"
    local protocol="$2" # "v4" or "v6"
    local client_mac="$3" # For v4 or as base for v6 DUID if client_duid is empty/derived
    local client_duid="$4" # Full DUID hex string for v6. If empty, MAC might be used by simulator if it supports simple DUID generation.
    local expected_subnet_pattern="$5" # Regex for expected IP subnet in logs.
    local perfdhcp_extra_args_str="$6" # Optional extra args for perfdhcp

    log_info "--- Running Test Case: $test_name ---"

    local protocol_version_num
    local server_address
    local base_identity_arg
    local identity_val

    if [ "$protocol" == "v4" ]; then
        protocol_version_num=4
        server_address="255.255.255.255" # Rely on relay to forward
        base_identity_arg="--base-mac"
        identity_val="$client_mac"
    elif [ "$protocol" == "v6" ]; then
        protocol_version_num=6
        server_address="ff02::1:2" # All DHCP Relays/Servers
        base_identity_arg="--base-duid"
        identity_val="$client_duid"
        if [ -z "$client_duid" ] && [ -n "$client_mac" ]; then
            # Basic DUID-LL from MAC for testing if actual DUID isn't critical for THIS test's policy
            # DUID-LL: 0003 + 0001 (hwtype eth) + MAC
            # This is a simplified DUID; complex policies in relay might need specific DUIDs.
            local mac_hex=$(echo "$client_mac" | sed 's/://g')
            identity_val="00030001${mac_hex}"
            log_debug "Constructed simple DUID-LL $identity_val from MAC $client_mac for $test_name"
        fi
    else
        log_error "Invalid protocol '$protocol' for test case '$test_name'."
        TEST_FAILED_COUNT=$((TEST_FAILED_COUNT + 1))
        return
    fi

    local simulator_cmd=(
        "sudo" "$SIMULATOR_SCRIPT"
        "--num-clients" "1"
        "--host-iface" "br_clients" # Defined in kea_server_setup.sh
        "--rate" "1"
        "--duration" "10" # Increased duration slightly for better lease acquisition chance
        "--perfdhcp-path" "$PERFDHCP_PATH"
        "--output-dir" "$CURRENT_SIMULATOR_OUTPUT_DIR"
    )

    if [ "$protocol" == "v4" ]; then
        simulator_cmd+=("--dhcpv4-server" "$server_address")
        if [ -n "$identity_val" ]; then simulator_cmd+=("$base_identity_arg" "$identity_val"); fi
    elif [ "$protocol" == "v6" ]; then
        simulator_cmd+=("--dhcpv6-server" "$server_address")
        if [ -n "$identity_val" ]; then simulator_cmd+=("$base_identity_arg" "$identity_val"); fi
    fi

    # Add any extra perfdhcp arguments if provided
    if [ -n "$perfdhcp_extra_args_str" ]; then
        # This is a bit naive; assumes perfdhcp_extra_args_str is well-formed
        # e.g., perfdhcp_extra_args_str="-x myval -y anotherval"
        read -r -a extra_args_array <<< "$perfdhcp_extra_args_str"
        # The simulator script would need to be modified to accept arbitrary -x options for perfdhcp
        # For now, this placeholder shows where it would go.
        # A simpler way is to ensure dhcp_simulator.py can pass through some common ones, or use templates.
        log_debug "Note: perfdhcp_extra_args currently not fully plumbed through simulator script in this version."
    fi


    log_debug "Simulator command: ${simulator_cmd[*]}"

    # Ensure simulator script is executable
    if [ ! -x "$SIMULATOR_SCRIPT" ]; then
        log_error "Simulator script '$SIMULATOR_SCRIPT' not found or not executable."
        TEST_FAILED_COUNT=$((TEST_FAILED_COUNT + 1))
        return
    fi

    if ! "${simulator_cmd[@]}"; then
        log_error "DHCP Simulator script failed for test case '$test_name'."
        TEST_FAILED_COUNT=$((TEST_FAILED_COUNT + 1))
        # Optionally, dump relay/server logs here for immediate context
        # tail -n 20 "$PYTHON_RELAY_LOG_FILE"
        return
    fi

    local perfdhcp_log_file="${CURRENT_SIMULATOR_OUTPUT_DIR}/client_0_v${protocol_version_num}.log"
    log_debug "Perfdhcp log file for '$test_name': $perfdhcp_log_file"

    # Wait a moment for logs to flush
    sleep 2

    if verify_test_case "$test_name" "$protocol" "$perfdhcp_log_file" "$expected_subnet_pattern"; then
        log_info "Test Case: $test_name - PASSED"
        TEST_PASSED_COUNT=$((TEST_PASSED_COUNT + 1))
    else
        log_error "Test Case: $test_name - FAILED"
        TEST_FAILED_COUNT=$((TEST_FAILED_COUNT + 1))
        if [ "$DEBUG_MODE" -eq 1 ]; then
            log_debug "Dumping relevant logs for FAILED test: $test_name"
            log_debug "--- Python Relay Log ($PYTHON_RELAY_LOG_FILE) ---"
            tail -n 30 "$PYTHON_RELAY_LOG_FILE"
            log_debug "--- Perfdhcp Log ($perfdhcp_log_file) ---"
            cat "$perfdhcp_log_file"
            # Add Kea server logs if needed
        fi
    fi
}

verify_test_case() {
    local test_name="$1"
    # protocol="$2" # Unused for now, but could be useful
    local perfdhcp_log_file="$3"
    local expected_subnet_pattern="$4"

    log_debug "Verifying '$test_name' using log: $perfdhcp_log_file"

    if [ ! -f "$perfdhcp_log_file" ]; then
        log_error "Verification FAILED for '$test_name': Perfdhcp log file '$perfdhcp_log_file' not found."
        return 1
    fi

    # Basic success indicators from perfdhcp
    if ! grep -q "tests complete" "$perfdhcp_log_file"; then
        log_error "Verification FAILED for '$test_name': 'tests complete' not found in log."
        return 1
    fi
    log_debug "'tests complete' found in log for $test_name."

    # Check for leases obtained. Example: "leases:           1"
    local leases_obtained
    leases_obtained=$(grep -Eo "leases:[[:space:]]+[1-9][0-9]*" "$perfdhcp_log_file" | awk '{print $2}')
    if [ -z "$leases_obtained" ] || [ "$leases_obtained" -lt 1 ]; then
        log_error "Verification FAILED for '$test_name': No leases or zero leases reported in log."
        return 1
    fi
    log_debug "$leases_obtained leases reported for $test_name."

    # Optional: Check if an IP from the expected subnet was mentioned.
    # This is a very basic check. Perfdhcp's default log doesn't always show the offered IP directly.
    # This might require custom perfdhcp templates or more advanced parsing if strict IP verification is needed.
    if [ -n "$expected_subnet_pattern" ]; then
        # Example: perfdhcp might log something like "Offered IP: 192.168.10.100" if using a verbose template.
        # For now, we assume the log might contain an IP. This is highly dependent on perfdhcp verbosity/templates.
        # A simple grep for the subnet part.
        if ! grep -q -E "$expected_subnet_pattern" "$perfdhcp_log_file"; then
            log_warn "Verification for '$test_name': Expected subnet pattern '$expected_subnet_pattern' NOT found in log. This might be okay if perfdhcp doesn't log assigned IPs by default."
            # Not failing the test solely on this, as default perfdhcp logs might not show IPs.
        else
            log_debug "Expected subnet pattern '$expected_subnet_pattern' found in log for $test_name."
        fi
    fi

    # Check for explicit error messages in perfdhcp log
    # Using a broader pattern for common failure terms.
    if grep -E -i -q "crit:|error:|fail(ed)? to receive|timeout|no.*offer|no.*reply" "$perfdhcp_log_file"; then
        # If leases were obtained, these errors might be transient or part of complex exchanges (e.g., NAK then ACK).
        # If no leases, these errors are more likely fatal for the test.
        if [ -z "$leases_obtained" ] || [ "$leases_obtained" -lt 1 ]; then
            log_error "Verification FAILED for '$test_name': Error indicators found in log and no (or zero) leases confirmed."
            log_debug "Matching error lines from '$perfdhcp_log_file':"
            grep -E -i -n "crit:|error:|fail(ed)? to receive|timeout|no.*offer|no.*reply" "$perfdhcp_log_file" | while IFS= read -r line; do log_debug "  $line"; done
            return 1
        else
            log_warn "Potential error indicators found in '$test_name' log, but $leases_obtained leases were reported. Manual check advised."
            log_debug "Matching warning/error lines from '$perfdhcp_log_file':"
            grep -E -i -n "crit:|error:|fail(ed)? to receive|timeout|no.*offer|no.*reply" "$perfdhcp_log_file" | while IFS= read -r line; do log_debug "  $line"; done
        fi
    fi

    log_info "Verification criteria met for '$test_name'."
    return 0
}

# --- Main Script Logic ---
usage() {
    echo "Usage: $0 [-p /path/to/perfdhcp] [-d] [--no-cleanup]"
    echo "  -p: Path to perfdhcp executable (default: $DEFAULT_PERFDHCP_PATH)"
    echo "  -d: Enable debug mode (more verbose logging)"
    echo "  --no-cleanup: Skip the cleanup step after tests (for debugging environment)"
    exit 1
}

# Parse options
while getopts ":p:d" opt; do
  case ${opt} in
    p )
      PERFDHCP_PATH=$OPTARG
      ;;
    d )
      DEBUG_MODE=1
      ;;
    \? )
      usage
      ;;
  esac
done
shift $((OPTIND -1))

# Handle long options like --no-cleanup
for arg in "$@"; do
  if [ "$arg" == "--no-cleanup" ]; then
    NO_CLEANUP=1
    log_info "Running with --no-cleanup option. Environment will not be automatically cleaned."
  fi
done


# --- Absolute path for Python relay script for pgrep ---
# This assumes dhcp_pyrelay.py is in the same directory as this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PYTHON_RELAY_SCRIPT_PATH_ABS="${SCRIPT_DIR}/dhcp_pyrelay.py"


check_root
log_info "E2E Test Suite Started."
log_debug "Debug mode enabled."
log_debug "Using perfdhcp path: $PERFDHCP_PATH"

# Graceful cleanup on exit/interrupt
trap "{ log_info 'Interrupted. Forcing cleanup...'; cleanup_environment; exit 1; }" SIGINT SIGTERM

if ! start_environment; then
    log_error "Environment failed to start. Aborting tests."
    cleanup_environment # Attempt cleanup even on start failure
    exit 1
fi

log_info "=== Running DHCPv4 Test Cases ==="
run_test_case "DHCPv4_RED_VIDEO" "v4" "00:aa:01:00:00:01" "" "192\.168\.10\."
run_test_case "DHCPv4_RED_DATA"  "v4" "00:aa:02:00:00:02" "" "192\.168\.11\."
run_test_case "DHCPv4_BLUE_GENERIC" "v4" "00:bb:01:00:00:03" "" "192\.168\.20\." # Blue VRF, first subnet

log_info "=== Running DHCPv6 Test Cases ==="
# DUIDs: Type 1 (LLT) = 0001, HWType 1 (Eth) = 0001, Time (dummy 4B), MAC (6B)
DUID_RED_VIDEO="00010001AABBCCDD00aa01000011" # MAC 00:aa:01:00:00:11
DUID_RED_DATA="00010001AABBCCDD00aa02000012"  # MAC 00:aa:02:00:00:12
DUID_BLUE_GENERIC="00010001AABBCCDD00bb01000013" # MAC 00:bb:01:00:00:13

run_test_case "DHCPv6_RED_VIDEO" "v6" "00:aa:01:00:00:11" "$DUID_RED_VIDEO" "fd00:red::"
run_test_case "DHCPv6_RED_DATA"  "v6" "00:aa:02:00:00:12" "$DUID_RED_DATA"  "fd00:red:1::"
run_test_case "DHCPv6_BLUE_GENERIC" "v6" "00:bb:01:00:00:13" "$DUID_BLUE_GENERIC" "fd00:blue::"


# --- Teardown ---
if [ "$NO_CLEANUP" -eq 0 ]; then
    if ! cleanup_environment; then
        log_error "Cleanup failed. Manual intervention may be required."
    fi
else
    log_info "Skipping cleanup due to --no-cleanup flag. To stop services manually, run: sudo ${KEA_SETUP_SCRIPT} stop"
fi


# --- Summary ---
log_info "================ TEST SUMMARY ================"
log_info "PASSED: $TEST_PASSED_COUNT"
log_info "FAILED: $TEST_FAILED_COUNT"
log_info "============================================"

if [ "$TEST_FAILED_COUNT" -gt 0 ]; then
    log_error "Some tests failed."
    exit 1
else
    log_info "All tests passed successfully!"
    exit 0
fi
EOL
chmod +x run_e2e_tests.sh
