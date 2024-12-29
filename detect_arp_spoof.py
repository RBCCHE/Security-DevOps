#!/usr/bin/python3
from scapy.all import ARP, sniff, getmacbyip
from datetime import datetime
import logging
import json
import os

class ARPSpoofDetector:
    def __init__(self, log_file="/home/kali/arp_detection.log"):
        self.log_file = log_file
        self.known_macs = {}  # Store known IP-MAC mappings
        self.attack_count = 0
        self.setup_logging()

    def setup_logging(self):
        """Configure logging with both file and console output"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ARP_Monitor')

    def save_attack_stats(self):
        """Save attack statistics to JSON file"""
        stats = {
            "total_attacks": self.attack_count,
            "known_attackers": list(self.known_macs.keys()),
            "last_updated": datetime.now().isoformat()
        }
        with open("/home/kali/arp_stats.json", "w") as f:
            json.dump(stats, f, indent=4)

    def detect_arp_spoof(self, pkt):
        """Detect ARP spoofing attempts with enhanced verification"""
        if ARP not in pkt or pkt[ARP].op != 2:  # Not an ARP reply
            return

        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        
        # Get real MAC address
        real_mac = getmacbyip(src_ip)
        
        # Check if this is the first time seeing this IP
        if src_ip not in self.known_macs:
            self.known_macs[src_ip] = src_mac
            self.logger.info(f"New IP-MAC mapping: {src_ip} -> {src_mac}")
            return

        # Check for MAC address mismatch
        if real_mac and real_mac != src_mac:
            self.attack_count += 1
            attack_info = {
                "timestamp": datetime.now().isoformat(),
                "type": "ARP Spoofing",
                "details": {
                    "victim_ip": src_ip,
                    "real_mac": real_mac,
                    "fake_mac": src_mac,
                    "severity": "HIGH"
                }
            }
            
            self.logger.warning(
                f"ARP SPOOF DETECTED!\n"
                f"Attacker MAC: {src_mac}\n"
                f"Pretending to be IP: {src_ip}\n"
                f"Real MAC should be: {real_mac}"
            )
            
            # Save detailed attack information
            with open("/home/kali/detailed_attacks.json", "a") as f:
                f.write(json.dumps(attack_info) + "\n")
            
            # Update statistics
            self.save_attack_stats()

    def start_monitoring(self, interface="eth0"):
        """Start ARP monitoring on specified interface"""
        self.logger.info(f"Starting ARP monitoring on interface {interface}")
        try:
            sniff(
                store=False, 
                prn=self.detect_arp_spoof, 
                filter="arp",
                iface=interface
            )
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
            self.save_attack_stats()
        except Exception as e:
            self.logger.error(f"Error during monitoring: {str(e)}")

def main():
    # Create log directory if it doesn't exist
    os.makedirs("/home/kali/logs", exist_ok=True)
    
    # Initialize and start detector
    detector = ARPSpoofDetector("/home/kali/logs/arp_detection.log")
    
    print("ARP Spoofing Detector Started")
    print("Press Ctrl+C to stop monitoring")
    
    detector.start_monitoring()

if __name__ == "__main__":
    main()