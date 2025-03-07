#!/bin/bash

LOG_FILE="/home/rb/mitm_detection_logs.txt"
DURATION=60  # Set capture duration in seconds (adjust as needed)

# Clear old logs
> $LOG_FILE

echo "[+] Monitoring network for ARP Spoofing attacks for $DURATION seconds..." | tee -a $LOG_FILE
echo "===========================================" >> $LOG_FILE
echo "[+] MITM Detection started at: $(date)" >> $LOG_FILE
echo "===========================================" >> $LOG_FILE

# Run tshark for a limited duration and save output
sudo timeout $DURATION tshark -i eth0 -n -Y "arp.opcode == 2" -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4 | tee -a $LOG_FILE

echo "[+] MITM Detection stopped at: $(date)" >> $LOG_FILE
echo "[+] Log saved to $LOG_FILE"
