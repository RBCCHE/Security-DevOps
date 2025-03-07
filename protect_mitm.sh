#!/bin/bash
echo "[+] Activation de la protection MITM sur Fortigate..."
ssh admin@fortigate "config firewall policy
edit 1
set action deny
set srcintf any
set dstintf any
set srcaddr all
set dstaddr all
set service ALL
set schedule always
next
end"
