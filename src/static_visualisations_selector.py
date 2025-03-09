import argparse
import curses
import pcap_analyzer

from static_visualisations.static_protocol_distribution import plot_protocols
from static_visualisations.static_data_usage import plot_data_usage
from static_visualisations.static_top_senders_receivers import plot_top_senders_receivers
from static_visualisations.static_network_topology import plot_network_topology
from static_visualisations.static_packet_size_distribution import plot_packet_size_distribution
from static_visualisations.static_flow_analysis import plot_flow_analysis
from static_visualisations.static_traffic_heatmap import plot_traffic_heatmap
#from static_visualisations.static_geolocation import plot_geolocation
#from static_visualisations.static_ttl_distribution import plot_ttl_distribution


def select_visualization(stdscr):
    visualizations = [
        "Objem dát v čase",
        "Distribúcia protokolov",
        "Top odosielatelia a prijímatelia",
        "Graf spojení - topológia siete",
        "Distribúcia veľkosti paketov",
        "Analýza tokov",
        "Tepelná mapa prevádzky",
        "Geolokácia",
        "Distribúcia TTL",
        "Výber špeciálnych vizualizácií na základe protokolu"
    ]

    current_selection = 0

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Zoznam dostupných vizualizácií:", curses.A_BOLD)

        for i, vis in enumerate(visualizations):
            if i == current_selection:
                stdscr.addstr(i + 2, 0, f"> {i + 1}. {vis}", curses.A_REVERSE)
            else:
                stdscr.addstr(i + 2, 0, f"  {i + 1}. {vis}")

        stdscr.addstr(len(visualizations) + 4, 0,
                      "Použite šípky na výber vizualizácie a stlačte ENTER. Stlačte 'q' pre ukončenie.")
        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP and current_selection > 0:
            current_selection -= 1
        elif key == curses.KEY_DOWN and current_selection < len(visualizations) - 1:
            current_selection += 1
        elif key == ord('\n'):  # ENTER key
            return str(current_selection + 1)  # Return the selected visualization number
        elif key == ord('q'):  # Quit option
            return "q"


def main(stdscr, pcap_file):
    while True:
        visualisation = select_visualization(stdscr)
        if visualisation == "q":
            break  # Exit on 'q'

        filters = {}
        filtered_packets = pcap_analyzer.analyze_packets(pcap_file, filters)

        # Temporarily exit curses mode to display the plot
        curses.endwin()

        if visualisation == "1":
            plot_data_usage(filtered_packets, pcap_file)
        elif visualisation == "2":
            plot_protocols(filtered_packets["protocol_counts"], pcap_file)
        elif visualisation == "3":
            plot_top_senders_receivers(filtered_packets, pcap_file)
        elif visualisation == "4":
            plot_network_topology(filtered_packets, pcap_file)
        elif visualisation == "5":
            plot_packet_size_distribution(filtered_packets, pcap_file)
        elif visualisation == "6":
            plot_flow_analysis(filtered_packets, pcap_file)
        elif visualisation == "7":
            plot_traffic_heatmap(filtered_packets, pcap_file)
#        elif visualisation == "8":
#            plot_geolocation(filtered_packets, pcap_file)
#       elif visualisation == "9":
#            plot_ttl_distribution(filtered_packets, pcap_file)

        # Reinitialize curses after plot is closed
        stdscr = curses.initscr()
        curses.curs_set(0)
        stdscr.keypad(True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zobrazenie komunikácie medzi dvomi zariadeniami.")
    parser.add_argument("pcap_file", type=str, help="Cesta k súboru PCAP")
    args = parser.parse_args()

    curses.wrapper(main, args.pcap_file)