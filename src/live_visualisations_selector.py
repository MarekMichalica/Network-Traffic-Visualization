import argparse
import curses
import json
from live_visualisations.live_plot_protocols import plot_protocols
from live_visualisations.live_data_usage import plot_data_usage

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

        stdscr.addstr(len(visualizations) + 4, 0, "Použite šípky na výber vizualizácie a stlačte ENTER. Stlačte 'q' pre ukončenie.")
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

def load_packets_from_json(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)  # Load the entire JSON data
        return data['packets']  # Return the list of packets

def main(stdscr, json_file):
    while True:
        visualisation = select_visualization(stdscr)
        if visualisation == "q":
            break  # Exit on 'q'

        # Load packets from the JSON file
        packets = load_packets_from_json(json_file)

        # Call the appropriate visualization based on user selection
        if visualisation == "1":
            plot_data_usage(r"live_visualisations/data_usage.json")  # Call the plot function
        elif visualisation == "2":
            filtered_packets = {
                "protocol_counts": {}
            }
            # Populate filtered_packets based on your JSON data
            for packet in packets:
                if isinstance(packet, dict):
                    protocol = packet['protocol']
                    # Update protocol counts
                    if protocol in filtered_packets["protocol_counts"]:
                        filtered_packets["protocol_counts"][protocol] += 1
                    else:
                        filtered_packets["protocol_counts"][protocol] = 1
            plot_protocols(filtered_packets["protocol_counts"], json_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zobrazenie komunikácie medzi dvomi zariadeniami.")
    parser.add_argument("json_file", type=str, help="Cesta k súboru JSON s paketmi")
    args = parser.parse_args()

    curses.wrapper(main, args.json_file)
