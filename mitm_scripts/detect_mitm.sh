#!/bin/bash

# Interface réseau (change en fonction de ta config)
INTERFACE="eth0"

# Durée de capture en secondes
DURATION=30

# Fichier temporaire pour stocker les paquets ARP
TEMP_FILE="/tmp/arp_scan.log"

# Nettoyage du fichier précédent
> "$TEMP_FILE"

echo "[INFO] Surveillance des paquets ARP pendant $DURATION secondes..."
tshark -i "$INTERFACE" -Y "arp.opcode == 2" -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4 > "$TEMP_FILE" &
TSHARK_PID=$!

# Attendre la fin de la capture
sleep "$DURATION"
kill "$TSHARK_PID"

echo "[INFO] Analyse des paquets ARP capturés..."
cat "$TEMP_FILE" | sort | uniq -c | sort -nr | while read count mac ip; do
    if [ "$count" -gt 1 ]; then
        echo "[ALERT] Possible MITM Attack detected! IP: $ip has multiple MAC addresses."
    fi
done

echo "[INFO] Surveillance terminée."
