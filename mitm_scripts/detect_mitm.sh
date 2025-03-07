#!/bin/bash

INTERFACE="eth0"  # Update if needed
DURATION=60
TEMP_FILE="/tmp/arp_scan.log"
LOG_FILE="/home/rb/mitm_detection_logs.txt"

# Clean previous logs
> "$TEMP_FILE"
> "$LOG_FILE"

echo "[INFO] Monitoring ARP packets for $DURATION seconds..." | tee -a "$LOG_FILE"
tshark -i "$INTERFACE" -Y "arp.opcode == 2" -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4 > "$TEMP_FILE" &
TSHARK_PID=$!

sleep "$DURATION"
kill "$TSHARK_PID"

echo "[INFO] Analyzing ARP packets..." | tee -a "$LOG_FILE"
cat "$TEMP_FILE" | sort | uniq -c | sort -nr | while read count mac ip; do
    if [ "$count" -gt 1 ]; then
        echo "[ALERT] MITM Attack detected! IP: $ip has multiple MAC addresses." | tee -a "$LOG_FILE"
    fi
done

echo "[INFO] Detection completed." | tee -a "$LOG_FILE"
