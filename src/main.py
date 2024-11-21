import argparse
import time
from datetime import datetime
from packet_analyzer import analyze_packets
from visualizations.protocol_distribution import plot_protocols


def main():
    parser = argparse.ArgumentParser(description="Analýza súboru PCAP.")
    parser.add_argument("pcap_file", type=str, help="Cesta k súboru PCAP")

    # IP filtre
    parser.add_argument("--src-ip", type=str, help="Zdrojová IP na filtrovanie paketov")
    parser.add_argument("--dst-ip", type=str, help="Cieľová IP na filtrovanie paketov")

    args = parser.parse_args()
    filters = vars(args)  # Konvertuje argumenty na slovník pre jednoduchšiu manipuláciu

    # Analyzovanie súboru PCAP a aplikácia filtrov
    packets = analyze_packets(args.pcap_file, filters)

    # Zobrazenie paketov
    print("\nPakety:\n")
    print("# | Časová pečiatka      | Zdrojová IP     | Cieľová IP      | Protokol | Zdroj. port | Cieľ. port | Veľkosť paketu | Dáta ")
    print("-" * 120)

    # Inicializácia predošlej časovej pečiatky na None pre prvý paket
    previous_timestamp = None

    for idx, packet_info in enumerate(packets["filtered_packets"], 1):
        # Analyzovanie aktuálnej časovej pečiatky ako objektu datetime
        current_timestamp = datetime.strptime(packet_info["timestamp"], "%Y-%m-%d %H:%M:%S")

        # Vypočítanie delta času od predošlého paketu
        if previous_timestamp:
            delta_time = (current_timestamp - previous_timestamp).total_seconds()
            # Pauza o delta čas pre simuláciu toku paketov v reálnom čase
            time.sleep(delta_time)
        else:
            delta_time = 0  # Žiadne oneskorenie pre prvý paket

        # Aktualizácia predošlej časovej pečiatky
        previous_timestamp = current_timestamp

        # Vypísanie informácií o pakete
        print(f"{idx:<2} | {packet_info['timestamp']} | {packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
              f"{packet_info['protocol']:<7} | {packet_info['src_port']:<8} | {packet_info['dst_port']:<8} | "
              f"{packet_info['size']:<5} bytes | {packet_info['payload']} |")

    # Vizualizácia výsledkov ako koláčový graf
    plot_protocols(packets["protocol_counts"], args.pcap_file)


if __name__ == "__main__":
    main()
