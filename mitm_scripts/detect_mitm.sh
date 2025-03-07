#!/bin/bash

LOG_FILE="/home/rb/mitm_detection_logs.txt"
DURATION=120  # Run for 120 seconds (2 minutes)
END_TIME=$((SECONDS + DURATION))

> $LOG_FILE

echo "[+] Monitoring network for ARP Spoofing attacks..."
echo "===========================================" >> $LOG_FILE
echo "[+] MITM Detection started at: $(date)" >> $LOG_FILE
echo "===========================================" >> $LOG_FILE

tshark -i eth0 -n -Y "arp.opcode == 2" -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4 2>/dev/null | \
while read -r mac ip; do
    if [[ $SECONDS -ge $END_TIME ]]; then
        echo "[+] Detection script stopped after $DURATION seconds." | tee -a $LOG_FILE
        break
    fi

    if grep -q "$ip" $LOG_FILE; then
        prev_mac=$(grep "$ip" $LOG_FILE | awk '{print $3}')
        if [[ "$prev_mac" != "$mac" ]]; then
            echo "[!] ALERT: Possible MITM Attack detected!" | tee -a $LOG_FILE
            echo "[!] IP $ip is now associated with $mac (previously $prev_mac)" | tee -a $LOG_FILE
        fi
    else
        echo "$ip - $mac" >> $LOG_FILE
    fi
done
