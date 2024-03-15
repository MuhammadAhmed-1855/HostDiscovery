import sys
from scapy.all import *

# Function definitions for drawing letters
def draw_h():
    return [
        "$     $ ",
        "$     $ ",
        "$     $ ",
        "$$$$$$$ ",
        "$     $ ",
        "$     $ ",
        "$     $ "
    ]

def draw_o():
    return [
        " $$$$$  ",
        "$     $ ",
        "$     $ ",
        "$     $ ",
        "$     $ ",
        "$     $ ",
        " $$$$$  "
    ]

def draw_s():
    return [
        " $$$$$ ",
        "$     $",
        "$      ",
        " $$$$$ ",
        "      $",
        "$     $",
        " $$$$$ "
    ]

def draw_t():
    return [
        "$$$$$$$$",
        "   $    ",
        "   $    ",
        "   $    ",
        "   $    ",
        "   $    ",
        "   $    "
    ]

def draw_hyphen():
    return [
        "        ",
        "        ",
        "        ",
        "$$$$$$$$",
        "        ",
        "        ",
        "        "
    ]

def draw_d():
    return [
        "$$$$$  ",
        "$    $ ",
        "$     $",
        "$     $",
        "$     $",
        "$    $ ",
        "$$$$$  "
    ]

def draw_i():
    return [
        "$",
        "$",
        "$",
        "$",
        "$",
        "$",
        "$"
    ]

def draw_c():
    return [
        " $$$$$$ ",
        "$      $",
        "$       ",
        "$       ",
        "$       ",
        "$      $",
        " $$$$$$ "
    ]

def draw_v():
    return [
        "$       $",
        "$       $",
        "$       $",
        " $     $ ",
        "  $   $  ",
        "   $ $   ",
        "    $    "
    ]

def draw_e():
    return [
        "$$$$$$",
        "$     ",
        "$     ",
        "$$$$$$",
        "$     ",
        "$     ",
        "$$$$$$"
    ]

def draw_r():
    return [
        "$$$$$$",
        "$    $",
        "$    $",
        "$$$$$$",
        "$  $  ",
        "$   $ ",
        "$    $"
    ]

def draw_y():
    return [
        "$     $",
        "$     $",
        " $   $ ",
        "  $ $  ",
        "   $   ",
        "   $   ",
        "   $   "
    ]


# Combine and print the letters in front of each other
for line in zip(draw_h(), draw_o(), draw_s(), draw_t(), draw_hyphen(), draw_d(), draw_i(), draw_s(), draw_c(), draw_o(), draw_v(), draw_e(), draw_r(), draw_y()):
    print(" ".join(line))

def print_menu():
    print("\nChoose the scan type:")
    print("0. Exit")
    print("1. ARP Ping Scan (Find IP addresses on current network)")
    print("2. ICMP Echo Ping (Ping a single IP address)")
    print("3. ICMP Echo Ping Sweep (Ping a range of IP addresses)")
    print("4. ICMP Timestamp Ping (Ping a single IP address)")
    print("5. ICMP Address Mask Ping (Ping a single IP address)")
    print("6. UDP Ping Scan (Ping a single IP address)")
    print("7. TCP SYN Scan (Scan for open TCP ports using SYN packets)")
    print("8. TCP ACK Scan (Scan for open TCP ports using ACK packets)")
    print("9. TCP Null Scan (Scan for open TCP ports using Null packets)")
    print("10. TCP XMAS Scan (Scan for open TCP ports using XMAS packets)")
    print("11. TCP FIN Scan (Scan for open TCP ports using FIN packets)")
    print("12. IP Protocol Ping Scan (Ping a single IP address for multiple protocols)")

def arp_ping_scan(network):
    print("ARP Ping Scan Results:")
    ans, unans = arping(network, timeout=2, verbose=False)
    if not ans:
        print("No response received from", network)
        return
    
    for sent, received in ans:
        print(received.psrc, "is up")

def icmp_echo_ping(target):
    print("ICMP Echo Ping Scan Results for", target)
    ans, unans = sr(IP(dst=target)/ICMP(type=8), timeout=2, verbose=False)
    if not ans:
        print("No response received from", target)
        return
    
    for sent, received in ans:
        print(received.src, "is up")

def icmp_echo_ping_sweep(network):
    print("ICMP Echo Ping Sweep Scan Results for", network)
    ans, unans = sr(IP(dst=network)/ICMP(type=8), timeout=2, verbose=False)
    if not ans:
        print("No response received from", network)
        return
    
    for sent, received in ans:
        print(received.src, "is up")

def icmp_timestamp_ping(target):
    print("ICMP Timestamp Ping Scan Results for", target)
    ans, unans = sr(IP(dst=target)/ICMP(type=13), timeout=2, verbose=False)
    if not ans:
        print("No response received from", target)
        return
    
    for sent, received in ans:
        print(received.src, "is up")

def icmp_address_mask_ping(target):
    print("ICMP Address Mask Ping Scan Results for", target)
    ans, unans = sr(IP(dst=target)/ICMP(type=17), timeout=2, verbose=False)
    if not ans:
        print("No response received from", target)
        return
    
    for sent, received in ans:
        print(received.src, "is up")

def udp_ping_scan(target):
    print("UDP Ping Scan Results for", target)
    ans, unans = sr(IP(dst=target)/UDP(dport=0), timeout=2, verbose=False)
    if not ans:
        print("No response received from", target)
        return
    
    for sent, received in ans:
        print(received.src, "is up")
        
def tcp_syn_scan(target, ports):
    print("TCP SYN Scan Results for", target)
    open_ports = []
    closed_ports = []
    for port in ports:
        response = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(port, "is open")
            open_ports.append(port)
        else:
            print(port, "is closed")
            closed_ports.append(port)
    
    if not open_ports:
        print("No open ports found.")
    if not closed_ports:
        print("All scanned ports are open.")
    
    return open_ports, closed_ports

def tcp_ack_scan(target, ports):
    print("TCP ACK Scan Results for", target)
    open_ports = []
    closed_ports = []
    for port in ports:
        response = sr1(IP(dst=target)/TCP(dport=port, flags="A"), timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x4:
            print(port, "is open")
            open_ports.append(port)
        else:
            print(port, "is closed")
            closed_ports.append(port)
    
    if not open_ports:
        print("No open ports found.")
    if not closed_ports:
        print("All scanned ports are open.")
    
    return open_ports, closed_ports

def tcp_null_scan(target, ports):
    print("TCP Null Scan Results for", target)
    open_ports = []
    closed_ports = []
    for port in ports:
        response = sr1(IP(dst=target)/TCP(dport=port, flags=""), timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            print(port, "is open")
            open_ports.append(port)
        else:
            print(port, "is closed")
            closed_ports.append(port)
    
    if not open_ports:
        print("No open ports found.")
    if not closed_ports:
        print("All scanned ports are open.")
    
    return open_ports, closed_ports

def tcp_xmas_scan(target, ports):
    print("TCP XMAS Scan Results for", target)
    open_ports = []
    closed_ports = []
    for port in ports:
        response = sr1(IP(dst=target)/TCP(dport=port, flags="FPU"), timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            print(port, "is open")
            open_ports.append(port)
        else:
            print(port, "is closed")
            closed_ports.append(port)
    
    if not open_ports:
        print("No open ports found.")
    if not closed_ports:
        print("All scanned ports are open.")
    
    return open_ports, closed_ports

def tcp_fin_scan(target, ports):
    print("TCP FIN Scan Results for", target)
    open_ports = []
    closed_ports = []
    for port in ports:
        response = sr1(IP(dst=target)/TCP(dport=port, flags="F"), timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            print(port, "is closed")
            closed_ports.append(port)
        else:
            print(port, "is open")
            open_ports.append(port)
    
    if not open_ports:
        print("No open ports found.")
    if not closed_ports:
        print("All scanned ports are open.")
    
    return open_ports, closed_ports

def ip_protocol_ping_scan(target):
    protocols = [1, 6, 17]  # ICMP, TCP, UDP
    print("IP Protocol Ping Scan Results for", target)
    open_ports = {}
    closed_ports = {}
    for proto in protocols:
        ans, unans = sr(IP(dst=target)/IP(proto=proto), timeout=2, verbose=False)
        for sent, received in ans:
            open_ports.setdefault(proto, []).append(received.src)
    
    for proto in protocols:
        if proto not in open_ports:
            closed_ports[proto] = []
    
    if not open_ports:
        print("No response received from", target)
    
    for proto, ips in open_ports.items():
        print(f"Protocol {proto}:")
        for ip in ips:
            print(f"{ip} is up")

def main():
    print("Welcome to Host Discovery Tool")
    while True:
        print_menu()
        choice = input("Enter your choice: ")

        if choice == '0':
            print("Exiting...")
            sys.exit(0)
        elif choice == '1':
            network = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
            arp_ping_scan(network)
        elif choice == '2':
            target = input("Enter the target IP address: ")
            icmp_echo_ping(target)
        elif choice == '3':
            network = input("Enter the network range to sweep (e.g., 192.168.1.0/24): ")
            icmp_echo_ping_sweep(network)
        elif choice == '4':
            target = input("Enter the target IP address: ")
            icmp_timestamp_ping(target)
        elif choice == '5':
            target = input("Enter the target IP address: ")
            icmp_address_mask_ping(target)
        elif choice == '6':
            target = input("Enter the target IP address: ")
            udp_ping_scan(target)
        elif choice == '7':
            target = input("Enter the target IP address: ")
            ports = input("Enter the port(s) to scan (comma-separated, e.g., 80,443): ").split(',')
            ports = [int(port.strip()) for port in ports]
            tcp_syn_scan(target, ports)
        elif choice == '8':
            target = input("Enter the target IP address: ")
            ports = input("Enter the port(s) to scan (comma-separated, e.g., 80,443): ").split(',')
            ports = [int(port.strip()) for port in ports]
            tcp_ack_scan(target, ports)
        elif choice == '9':
            target = input("Enter the target IP address: ")
            ports = input("Enter the port(s) to scan (comma-separated, e.g., 80,443): ").split(',')
            ports = [int(port.strip()) for port in ports]
            tcp_null_scan(target, ports)
        elif choice == '10':
            target = input("Enter the target IP address: ")
            ports = input("Enter the port(s) to scan (comma-separated, e.g., 80,443): ").split(',')
            ports = [int(port.strip()) for port in ports]
            tcp_xmas_scan(target, ports)
        elif choice == '11':
            target = input("Enter the target IP address: ")
            ports = input("Enter the port(s) to scan (comma-separated, e.g., 80,443): ").split(',')
            ports = [int(port.strip()) for port in ports]
            tcp_fin_scan(target, ports)
        elif choice == '12':
            target = input("Enter the target IP address: ")
            ip_protocol_ping_scan(target)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
