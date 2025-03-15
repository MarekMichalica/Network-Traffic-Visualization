import argparse
import curses
import os

from live_visualisations.live_plot_protocols import plot_protocols
from live_visualisations.live_data_usage import plot_data_usage
from live_visualisations.live_top_senders_recievers import plot_top_senders_receivers
from live_visualisations.live_topology import plot_network_topology
from live_visualisations.live_packet_size_distribution import plot_packet_size_distribution
from live_visualisations.live_flow_analysis import plot_flow_analysis

def select_visualization(stdscr):
    visualizations = [
        "Objem dát v čase",
        "Distribúcia protokolov",
        "Top odosielatelia a prijímatelia",
        "Graf spojení - topológia siete",
        "Distribúcia veľkosti paketov",
        "Analýza tokov",
        "Tepelná mapa prevádzky",
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
def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def main(stdscr, json_file):
    # Ensure the live_visualisations directory exists
    ensure_directory_exists("live_visualisations")

    while True:
        visualisation = select_visualization(stdscr)
        if visualisation == "q":
            break  # Exit on 'q'
        if visualisation == "1":
            plot_data_usage(r"live_visualisations/data_usage.json")
        elif visualisation == "2":
            plot_protocols(json_file)
        elif visualisation == "3":
            # Top senders and receivers
            plot_top_senders_receivers(json_file)
        elif visualisation == "4":
            # Network topology graph
            plot_network_topology(json_file)
        elif visualisation == "5":
            # Packet size distribution
            plot_packet_size_distribution(json_file)
        elif visualisation == "6":
            # Flow analysis
            plot_flow_analysis(json_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zobrazenie komunikácie medzi dvomi zariadeniami.")
    parser.add_argument("json_file", type=str, help="Cesta k súboru JSON s paketmi")
    args = parser.parse_args()

    curses.wrapper(main, args.json_file)