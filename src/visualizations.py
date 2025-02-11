import argparse
import curses
from packet_analyzer import analyze_packets
from visualizations.protocol_distribution import plot_protocols

def get_user_input(stdscr):
    curses.echo()
    stdscr.clear()
    stdscr.addstr(0, 0, "Zoznam dostupných vizualizácií:")
    stdscr.addstr(2, 0, "1. Objem dát v čase")
    stdscr.addstr(3, 0, "2. Distribúcia protokolov")
    stdscr.addstr(4, 0, "3. Top odosielatelia a prijímatelia")
    stdscr.addstr(5, 0, "4. Graf spojení - topológia siete")
    stdscr.addstr(6, 0, "5. Distribúcia veľkosti paketov")
    stdscr.addstr(7, 0, "6. Analýza tokov")
    stdscr.addstr(8, 0, "7. Tepelná mapa prevádzky")
    stdscr.addstr(9, 0, "8. Geolokácia")
    stdscr.addstr(10, 0, "9. Distribúcia TTL")
    stdscr.addstr(11, 0, "10. Výber špeciálnych vizualizácií na základe protokolu")
    stdscr.addstr(13, 0, "Zo zoznamu vyberte číslo požadovanej vizualizácie alebo stlačte 'q' pre ukončenie:")
    stdscr.refresh()
    return stdscr.getstr(14, 0).decode('utf-8')

def main(stdscr, pcap_file):
    i = 1
    while i:
        visualisation = get_user_input(stdscr)
        filters = {}
        packets = analyze_packets(pcap_file, filters)

        if visualisation == "2":
            plot_protocols(packets["protocol_counts"], pcap_file)
        elif visualisation == "q":
            break;

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zobrazenie komunikácie medzi dvomi zariadeniami.")
    parser.add_argument("pcap_file", type=str, help="Cesta k súboru PCAP")
    args = parser.parse_args()

    curses.wrapper(main, args.pcap_file)  # Pass pcap_file to main
