from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

# Callback function to handle each captured packet
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: ")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for TCP or UDP layers for port information
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        # Display payload data if available
        if packet.haslayer(Raw):
            print(f"Payload Data: {packet[Raw].load}")

# Main function to start sniffing
def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=packet_callback, store=False)

# Run the packet sniffer on a specified network interface
if __name__ == "__main__":
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    start_sniffing(interface)
