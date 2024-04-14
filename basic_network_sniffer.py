from scapy.all import sniff, Ether, IP, TCP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        else:
            print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")

def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
