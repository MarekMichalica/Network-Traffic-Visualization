from scapy.all import rdpcap
from collections import Counter
from datetime import datetime
from filters import ip_filter


def analyze_packets(file_path, filters):
    packets = rdpcap(file_path)
    protocol_counts = Counter()
    filtered_packets = []

    for packet in packets:
        try:
            if not (
                    ip_filter.match_ip(packet, filters)
            ):
                continue

            # Uloženie informácií o pakete
            packet_info = {
                "timestamp": datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": packet["IP"].src if packet.haslayer("IP") else "N/A",
                "dst_ip": packet["IP"].dst if packet.haslayer("IP") else "N/A",
                "protocol": {6: "TCP", 17: "UDP", 1: "ICMP", 80: "HTTP"}.get(packet["IP"].proto, "Other") if packet.haslayer("IP") else "N/A",
                "src_port": packet["TCP"].sport if packet.haslayer("TCP") else (
                    packet["UDP"].sport if packet.haslayer("UDP") else "N/A"),
                "dst_port": packet["TCP"].dport if packet.haslayer("TCP") else (
                    packet["UDP"].dport if packet.haslayer("UDP") else "N/A"),
                "size": len(packet),
                "payload": "N/A"
            }

            # Spracovanie protokolu HTTP
            if packet.haslayer("TCP") and packet["TCP"].dport == 80:
                packet_info["protocol"] = "HTTP"
                http_data = ""

                # Kontrola existencie RAW vrstvy
                if packet.haslayer("Raw"):
                    raw_data = packet["Raw"].load.decode(errors="ignore")

                    # Na základe nájdenia metód nájdené HTTP dáta
                    if raw_data.startswith("GET") or raw_data.startswith("POST"):
                        http_data += f"Method: {raw_data.split(' ')[0]} "
                        # Dáta hlavičky HTTp
                        lines = raw_data.split("\r\n")
                        for line in lines[1:]:
                            if line.startswith("Host"):
                                http_data += f"Host: {line.split(':')[1].strip()}"
                        packet_info["payload"] = http_data if http_data else "N/A"
                    else:
                        packet_info["payload"] = "N/A"
                else:
                    packet_info["payload"] = "N/A"
            else:
                packet_info["payload"] = "N/A"


            filtered_packets.append(packet_info)

            # Aktualizácia počtu protokolov
            protocol_counts[packet_info["protocol"]] += 1

        except Exception as e:
            print(e)

    return {
        "protocol_counts": protocol_counts,
        "filtered_packets": filtered_packets
    }
