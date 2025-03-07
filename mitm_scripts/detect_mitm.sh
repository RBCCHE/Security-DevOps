#!/bin/bash

INTERFACE="eth0"  # Change en fonction de ta config
DURATION=30
TEMP_FILE="/tmp/arp_scan.log"
LOG_FILE="/home/rb/mitm_detection_logs.txt"  # Fichier où les logs seront enregistrés

# Nettoyage des fichiers précédents
> "$TEMP_FILE"
> "$LOG_FILE"

echo "[INFO] Surveillance des paquets ARP pendant $DURATION secondes..." | tee -a "$LOG_FILE"
tshark -i "$INTERFACE" -Y "arp.opcode == 2" -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4 > "$TEMP_FILE" &
TSHARK_PID=$!

sleep "$DURATION"
kill "$TSHARK_PID"

echo "[INFO] Analyse des paquets ARP capturés..." | tee -a "$LOG_FILE"
cat "$TEMP_FILE" | sort | uniq -c | sort -nr | while read count mac ip; do
    if [ "$count" -gt 1 ]; then
        echo "[ALERT] Possible MITM Attack detected! IP: $ip has multiple MAC addresses." | tee -a "$LOG_FILE"
    fi
done

echo "[INFO] Surveillance terminée." | tee -a "$LOG_FILE"
