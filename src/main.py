import argparse
from packet_analyzer import analyze_packets
from visualizations.protocol_distribution import plot_protocols


def main():
    parser = argparse.ArgumentParser(description="PCAP file analyzer.")
    parser.add_argument("pcap_file", type=str, help="Path to the PCAP file")

    # IP filtre
    parser.add_argument("--src-ip", type=str, help="Source IP to filter packets by")
    parser.add_argument("--dst-ip", type=str, help="Destination IP to filter packets by")

    args = parser.parse_args()
    filters = vars(args)  # Previesť argumenty na slovník pre ľahšie spracovanie

    # Analyzovanie PCAP súboru a aplikovanie filtrov
    packets = analyze_packets(args.pcap_file, filters)

    # Výpis paketov
    print("\nFiltered Packets:\n")
    print("# | Timestamp            | Source IP       | Destination IP  | Protocol | Src Port | Dst Port | Packet Size | Data ")
    print("-" * 100)
    for idx, packet_info in enumerate(packets["filtered_packets"], 1):
        print(f"{idx:<2} | {packet_info['timestamp']} | {packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
              f"{packet_info['protocol']:<7} | {packet_info['src_port']:<8} | {packet_info['dst_port']:<8} | "
              f"{packet_info['size']:<5} bytes | {packet_info['payload']} |")

    #Vizualizácia výsledkov ako koláčový graf
    plot_protocols(packets["protocol_counts"], args.pcap_file)

if __name__ == "__main__":
    main()
