from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        #0: HOPOPT
        #1: ICMP
        #2: IGMP
        #6: TCP
        #17: UDP
        #41: IPv6
        #50: ESP
        #51: AH
        #89: OSPF
        if protocol == 1:
            proto = "ICMP"
        elif protocol == 6:
            proto = "TCP"
        elif protocol == 17:
            proto = "UDP"
        else:
            proto = "Other"


        print(f"IP Packet: {ip_src} -> {ip_dst} (Protocol: {proto})")
        if proto == "TCP" and TCP in packet:
            print(f"TCP Packet: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")
        elif proto == "UDP" and UDP in packet:
            print(f"UDP Packet: {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}")
        elif proto == "ICMP" and ICMP in packet:
            print(f"ICMP Packet: {ip_src} -> {ip_dst} (Type: {packet[ICMP].type})")


# Start the sniffer
print("Starting the sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
