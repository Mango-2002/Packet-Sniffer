# Packet-Sniffer

# Network Packet Sniffer 🔎

A minimal yet functional **Network Packet Sniffer** developed during my Cyber Security Internship with [OutriX](https://www.linkedin.com/company/outrix/).

## ✨ Features
✅ Capture live network packets in real time  
✅ Display source IP, destination IP, protocol, and packet size  
✅ Filter packets by protocol or host using BPF syntax (e.g., `tcp`, `udp`, `host 8.8.8.8`)  
✅ Simple Tkinter GUI for starting/stopping capture and viewing logs  
✅ Export captured logs to a text file  
✅ Clear logs easily with one click  

## 🛠 Tech Stack
- **Python 3**
- **Scapy** (for packet sniffing)
- **Tkinter** (for the GUI)

## 📦 Installation
1. Clone this repository:
   ```bash
   git clone <https://github.com/Mango-2002/Packet-Sniffer/>
   cd <Packet-Sniffer>


python3 -m venv venv
source venv/bin/activate


pip install scapy


sudo python3 packet_sniffer_gui.py
