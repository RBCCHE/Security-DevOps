#!/bin/bash
echo "[+] Vérification des logs Fortigate pour détecter MITM..."
ssh admin@fortigate "diagnose sniffer packet any 'arp and ether[6:2] == 0x0002' 4"
