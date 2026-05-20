from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
import os

captured_packets = []

def process_packet(packet):
    """
    Callback function executed every time a new packet is captured.
    """
    captured_packets.append(packet)
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"
        else:
            protocol = "Other"
            src_port = "N/A"
            dst_port = "N/A"

        print(f"\n[+] {protocol} Packet: {ip_src}:{src_port} --> {ip_dst}:{dst_port}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload: {repr(payload[:50])}...")
        else:
            print("    Payload: None")

if __name__ == "__main__":
    print("Starting network sniffer... Press Ctrl+C to stop.")
    
    try:
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
        
        if captured_packets:
            output_file = "captured_traffic.pcap"
            wrpcap(output_file, captured_packets)
            print(f"Saved {len(captured_packets)} packets to {output_file}")