import argparse
import time
from datetime import datetime
import curses
from packet_analyzer import analyze_packets
from visualizations.protocol_distribution import plot_protocols


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

    # Argumenty pre analýzu PCAP
    parser = argparse.ArgumentParser(description="Analýza súboru PCAP.")
    parser.add_argument("pcap_file", type=str, help="Cesta k súboru PCAP")
    parser.add_argument("--src-ip", type=str, help="Zdrojová IP na filtrovanie paketov")
    parser.add_argument("--dst-ip", type=str, help="Cieľová IP na filtrovanie paketov")
    args = parser.parse_args()
    filters = vars(args)

    # Analyzovanie súboru PCAP a aplikácia filtrov
    packets = analyze_packets(args.pcap_file, filters)

    # Počet paketov
    total_packets = len(packets["filtered_packets"])

    # Inicializácia predošlej časovej pečiatky
    previous_timestamp = None
    progress_bar_width = 50  # Šírka progres baru
    current_value = 1  # Počiatočný progres

    # Sledovanie výpisu riadkov tabuľky
    line_offset = 4  # Začneme vypisovať pakety od riadku 4

    # Získame šírku a výšku obrazovky
    max_y, max_x = stdscr.getmaxyx()

    # Uložíme si už vypísané riadky, aby sme ich mohli rolovať
    packet_lines = []

    # Počet paketov podľa protokolov
    protocol_counts = {protocol: 0 for protocol in packets["protocol_counts"].keys()}

    # Calculate the total number of packets for all protocols
    total_protocols = sum(protocol_counts.values())

    # Vytvorenie pokroku pre každý protokol
    protocol_progress = {protocol: 0 for protocol in protocol_counts.keys()}

    # Vypisovanie všetkých paketov
    for idx, packet_info in enumerate(packets["filtered_packets"], 1):
        # Analyzovanie časovej pečiatky
        current_timestamp = datetime.strptime(packet_info["timestamp"], "%Y-%m-%d %H:%M:%S")

        # Vypočítanie delta času od predošlého paketu
        if previous_timestamp:
            delta_time = (current_timestamp - previous_timestamp).total_seconds()
            time.sleep(delta_time)  # Pauza na simuláciu toku paketov v reálnom čase
        previous_timestamp = current_timestamp

        # Vypočítanie počtu '#' pre progres bar (celkový progres)
        num_hashes = int((current_value / total_packets) * progress_bar_width)

        # Aktualizácia progres baru
        progress_bar = f"Progress: [{'#' * num_hashes}{' ' * (progress_bar_width - num_hashes)}] {current_value}/{total_packets}"

        # Posúvanie obsahu obrazovky
        stdscr.clear()

        # Zobrazenie progres baru na vrchu obrazovky
        stdscr.addstr(1, 0, progress_bar)

        # Aktualizácia počtu paketov pre každý protokol
        protocol_counts[packet_info["protocol"]] += 1

        # Vypočítať percento pokroku pre každý protokol a zobraziť
        protocol_y_offset = 2  # Starting line for protocol progress bars
        for protocol, count in protocol_counts.items():
            protocol_percentage = (count / total_packets) * 100  # Percento pre daný protokol
            num_hashes_protocol = int((protocol_percentage / 100) * progress_bar_width)  # Počet symbolov #

            protocol_bar = f"{protocol}: [{'#' * num_hashes_protocol}{' ' * (progress_bar_width - num_hashes_protocol)}] {protocol_percentage:.2f}%"
            stdscr.addstr(protocol_y_offset, 0, protocol_bar)
            protocol_y_offset += 1

        # Zobrazenie hlavičky tabuľky
        stdscr.addstr(protocol_y_offset, 0, "# | Časová pečiatka      | Zdrojová IP     | Cieľová IP      | Protokol | Zdroj. port | Cieľ. port | Veľkosť paketu | Dáta ")
        stdscr.addstr(protocol_y_offset + 1, 0, "-" * 120)

        # Príprava textu pre aktuálny paket
        packet_info_str = (f"{idx:<2} | {packet_info['timestamp']} | {packet_info['src_ip']:<15} | {packet_info['dst_ip']:<15} | "
                           f"{packet_info['protocol']:<7} | {packet_info['src_port']:<6} | {packet_info['dst_port']:<6} | "
                           f"{packet_info['size']:<5} bytes | {packet_info['payload']}")

        # Zabalíme dáta, aby sa zmestili do šírky obrazovky
        wrapped_lines = wrap_text(packet_info_str, max_x - 2)

        # Pridanie riadkov do zoznamu
        for line in wrapped_lines:
            if len(packet_lines) >= max_y - protocol_y_offset - 4:  # Ak počet riadkov presahuje obrazovku, vymažeme najstaršie
                packet_lines.pop(0)

            packet_lines.append(line)

        # Zobrazenie všetkých riadkov (paketov)
        for i, line in enumerate(packet_lines, start=protocol_y_offset + 2):
            stdscr.addstr(i, 0, line)

        # Inkrementácia hodnoty progresu
        current_value += 1

        # Obnovenie obrazovky
        stdscr.refresh()

    # Po dokončení, vykreslíme graf (koláčový graf)
    # plot_protocols(packets["protocol_counts"], args.pcap_file)

    #Zobrazenie dokončenia procesu
    stdscr.addstr(line_offset + len(packet_lines) + 3, 0, "Výpis obsahu PCAP súboru prebehol úspešne. Stlačte tlačidlo pre ukončenie programu")
    #stdscr.refresh()
    stdscr.getch()  # Čaká na stlačenie klávesy


if __name__ == "__main__":
    curses.wrapper(main)