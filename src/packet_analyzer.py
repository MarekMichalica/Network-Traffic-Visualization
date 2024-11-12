from scapy.all import rdpcap
from collections import Counter
from datetime import datetime
from src.filters import ip_filter


def analyze_packets(file_path, filters):
    packets = rdpcap(file_path)
    protocol_counts = Counter()
    filtered_packets = []

    for packet in packets:
        if not (
                ip_filter.match_ip(packet, filters)
        ):
            continue

        # Uloženie informácií o pakete
        packet_info = {
            "timestamp": datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": packet["IP"].src if packet.haslayer("IP") else "N/A",
            "dst_ip": packet["IP"].dst if packet.haslayer("IP") else "N/A",
            "protocol": {6: "TCP", 17: "UDP", 1: "ICMP", 80: "HTTP"}.get(packet["IP"].proto, "Other") if packet.haslayer(
                "IP") else "N/A",
            "src_port": packet["TCP"].sport if packet.haslayer("TCP") else (
                packet["UDP"].sport if packet.haslayer("UDP") else "N/A"),
            "dst_port": packet["TCP"].dport if packet.haslayer("TCP") else (
                packet["UDP"].dport if packet.haslayer("UDP") else "N/A"),
            "size": len(packet)
        }

        if packet.haslayer("TCP") and packet["TCP"].dport == 80:
            packet_info["protocol"] = "HTTP"

        filtered_packets.append(packet_info)

        # Aktualizácia počtu protokolov
        protocol_counts[packet_info["protocol"]] += 1

    return {
        "protocol_counts": protocol_counts,
        "filtered_packets": filtered_packets
    }
