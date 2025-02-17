import argparse
import time
from datetime import datetime
import curses
import subprocess
from packet_analyzer import analyze_packets, interface_analyzer

def clean_string(input_str):
    """Odstráni null characters a iné neplatné znaky z reťazca."""
    return input_str.replace('\0', '')  # Odstráni null characters

def wrap_text(text, width):
    """Zabalí text na riadky s maximálnou šírkou."""
    lines = []
    while len(text) > width:
        split_point = text.rfind(' ', 0, width)  # Nájdeme posledný medzeru do šírky
        if split_point == -1:  # Ak nie je medzera, orežeme na pevnú šírku
            split_point = width
        lines.append(text[:split_point])
        text = text[split_point:].lstrip()  # Orezanie textu a odstránenie medzier
    lines.append(text)  # Pridáme posledný riadok
    return lines

def main(stdscr):
    # Vyčistenie obrazovky
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    # Argumenty pre analýzu PCAP
    parser = argparse.ArgumentParser(description="Zobrazenie komunikácie medzi dvomi zariadeniami.")
    parser.add_argument("pcap_file", type=str, help="Cesta k súboru PCAP")
    parser.add_argument("--ip_a", type=str, help="IP adresa prvého zariadenia (voliteľné)")
    parser.add_argument("--ip_b", type=str, help="IP adresa druhého zariadenia (voliteľné)")
    args = parser.parse_args()

    # Inicializácia filtrov
    filters = {}

    # Ak sú zadané, pridať ich ako filtre
    if args.ip_a:
        filters["ip_a"] = args.ip_a
    if args.ip_b:
        filters["ip_b"] = args.ip_b

    # Ak neexistujú žiadne filtre, odovzdáme None (aby analyzér použil všetky pakety)
    if not filters:
        filters = None

    # Analyzovanie súboru PCAP a aplikácia filtrov
    packets = analyze_packets(args.pcap_file, filters)

    # Počet paketov
    total_packets = len(packets["filtered_packets"])

    previous_timestamp = None
    progress_bar_width = 50  # Šírka progres baru
    current_value = 1  # Počiatočný progres
    packet_lines = []
    remaining_packets = total_packets
    protocol_counts = {protocol: 0 for protocol in packets["protocol_counts"].keys()}

    # Nastavenie timeoutu na 100 ms pre neblokujúce čítanie kláves
    stdscr.timeout(100)
    run_subprocess = False

    while remaining_packets and not run_subprocess:
        for idx, packet_info in enumerate(packets["filtered_packets"], 1):
            current_timestamp = datetime.strptime(packet_info["timestamp"], "%Y-%m-%d %H:%M:%S")

            if previous_timestamp:
                delta_time = (current_timestamp - previous_timestamp).total_seconds()
                time.sleep(delta_time)
            previous_timestamp = current_timestamp

            num_hashes = int((current_value / total_packets) * progress_bar_width)
            progress_bar = f"Progress: [{'#' * num_hashes}{' ' * (progress_bar_width - num_hashes)}] {current_value}/{total_packets}"

            stdscr.clear()

            stdscr.addstr(1, 0, progress_bar)
            protocol_counts[packet_info["protocol"]] += 1

            protocol_y_offset = 2
            for protocol, count in protocol_counts.items():
                protocol_percentage = (count / total_packets) * 100
                num_hashes_protocol = int((protocol_percentage / 100) * progress_bar_width)

                protocol_bar = f"{protocol}: [{'#' * num_hashes_protocol}{' ' * (progress_bar_width - num_hashes_protocol)}] {protocol_percentage:.2f}%"
                stdscr.addstr(protocol_y_offset, 0, protocol_bar)
                protocol_y_offset += 1

            stdscr.addstr(protocol_y_offset, 0, "# | Časová pečiatka      | Zdrojová IP     | Cieľová IP      | Protokol | Porty       | Veľkosť     | Dáta ")
            stdscr.addstr(protocol_y_offset + 1, 0, "-" * 120)

            packet_info_str = (f"{idx:<2} | {packet_info['timestamp']} | {packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
                               f"{packet_info['protocol']:<8} | {packet_info['src_port']} -> {packet_info['dst_port']} | "
                               f"{packet_info['size']:<5} bytes | {packet_info['payload']}")

            wrapped_lines = wrap_text(packet_info_str, max_x - 2)

            for line in wrapped_lines:
                if len(packet_lines) >= max_y - protocol_y_offset - 4:
                    packet_lines.pop(0)

                clean_line = clean_string(line)
                packet_lines.append(clean_line)

            for i, line in enumerate(packet_lines, start=protocol_y_offset + 2):
                stdscr.addstr(i, 0, line)

            # Aktualizácia hlášky o ukončení na spodku obrazovky
            stdscr.addstr(max_y - 5, 0, str(remaining_packets))
            stdscr.addstr(max_y - 4, 0, "MENU: A) Vizualizácia 2 zariadení podľa IP B) Filtrovanie C) Vizualizácia".center(max_x))
            stdscr.addstr(max_y - 3, 0, "D) Export (JSON/CSV) E) ŠTART/STOP zachytávania F) Koniec".center(max_x))

            current_value += 1
            remaining_packets -= 1


            # Kontrola na stlačenú klávesu (non-blocking)
            key = stdscr.getch()
            if key == ord('A') or key == ord('a'):
                stdscr.clear()
                stdscr.refresh()

                subprocess.run([
                    "python", r"two_devices.py",
                ])
                return
            elif key == ord('C') or key == ord('c'):
                stdscr.clear()
                stdscr.refresh()

                subprocess.run([
                    "python", r"visualizations.py", args.pcap_file
                ])
                return

            elif key == ord('f') or key == ord('F'):
                return

            stdscr.refresh()

            if remaining_packets == 1:
                stdscr.clear()
                stdscr.addstr(max_y - 4, 0, "Vizualizácia paketov bola dokončená.".center(max_x))
                stdscr.refresh()

                key = stdscr.getstr(max_y, 0).decode('utf-8')
                if key == ord('f') or key == ord('F'):
                    return
                else: time.sleep(20)

    stdscr.refresh()

if __name__ == "__main__":
    curses.wrapper(main)
