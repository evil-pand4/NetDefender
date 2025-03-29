# NetDefender

This is a Python-based network monitoring script using Scapy. It detects:

- ARP spoofing attacks  
- Suspicious DNS queries based on entropy analysis

---

## Features

- Detects ARP spoofing (conflicting IP-MAC pairs)  
- Detects potentially malicious, randomized domains (high-entropy DNS queries)  
- Real-time packet sniffing using Scapy  
- Console or file logging  
- Graceful shutdown with CTRL+C  

---

## Requirements

- Python 3.x  
- Scapy (`pip install scapy`)  
- Root privileges to sniff packets  

