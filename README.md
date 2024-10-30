# PRODIGY_CS_05

This example uses Python’s scapy library to capture packets and extract information like source and destination IP addresses, protocol, and payload data.

# Prerequisites
You’ll need the scapy library, which can be installed with:

>> pip install scapy

# Explanation
packet_callback(packet): This function is called every time a packet is captured. It checks if the packet has an IP layer, then extracts and prints the source and destination IP addresses, protocol, and port information (if TCP or UDP). If there is a raw payload, it displays that as well.
start_sniffing(interface=None): This function initiates packet sniffing on a specific network interface provided by the user. The store=False option ensures that packets aren’t saved in memory, which keeps the program lightweight.

# Ethical Notes
Testing Environment: Run this tool only on your local machine or within a secure and authorized network for testing.
Permission and Authorization: Ensure you have authorization to capture packets on the network. Unauthorized packet sniffing may violate privacy laws and network policies.
Purpose: This code is designed for educational and diagnostic purposes only.
