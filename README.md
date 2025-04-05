
# 🛠 PANDIOT - Network Exploitation & ARP Spoofing Tool

**Author:** [cyber.soluti0ns](https://instagram.com/cyber.soluti0ns)  
**Location:** Purulia, West Bengal, India  
**Language:** Python  
**Platform:** Linux (Kali, Parrot, Ubuntu, Termux via Proot-distro)  
**Category:** Ethical Hacking / MITM / Packet Sniffing

---

## 🚀 Description

**BANDIOT** is a Python-based network exploitation tool designed for ethical hackers and cybersecurity enthusiasts. It enables you to scan local networks, perform ARP spoofing (Man-in-the-Middle attacks), and sniff live packets.  

Built with Scapy, Colorama, and netifaces, it provides a sleek CLI interface with colored output and clean handling of interruptions (like restoring ARP tables on `CTRL+C`).

---

## ⚙️ Features

- 🌐 Network Scanning (detects all IPs and MACs)
- 👤 ARP Spoofing / MITM Attacks
- 📡 Live Packet Sniffing (like Wireshark CLI)
- 📛 Auto ARP table restoration on exit
- 🎨 Colored Terminal Output
- 💻 Compatible with Linux and Termux (via root or proot)

---

## 📦 Installation & Running (1 Command Setup)

```bash
git clone https://github.com/your-username/bandiot.git && cd bandiot && pip install -r requirements.txt && sudo python3 bandiot.py

> ✅ Make sure you are running this as root (sudo or Termux root shell if needed).



> 💡 On Termux? Use proot-distro to install a Linux distro like Kali or Ubuntu first, then run the tool inside that.


🧰 Requirements

Python 3.x

Linux OS (Kali, Ubuntu, Parrot, or Termux w/ proot)

Root Access (or sudo rights)

Python Libraries:

scapy

colorama

netifaces


🖥️ Tool Menu

[1] Scan Network
[2] ARP Spoof (MITM)
[3] Sniff Packets
[4] Exit

🧑‍⚖️ Disclaimer

> ⚠️ This tool is intended only for educational and authorized penetration testing purposes.
Unauthorized usage is illegal and unethical. Use it responsibly.
