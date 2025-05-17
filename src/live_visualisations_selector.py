import argparse
import curses
import os
import json

from live_visualisations.live_plot_protocols import plot_protocols
from live_visualisations.live_data_usage import plot_data_usage
from live_visualisations.live_top_senders_recievers import plot_top_senders_receivers
from live_visualisations.live_topology import plot_network_topology
from live_visualisations.live_packet_size_distribution import plot_packet_size_distribution
from live_visualisations.live_flow_analysis import plot_flow_analysis

from specific_visualisations.tcp_flags import plot_tcp_flags
from specific_visualisations.tcp_retransmissions import plot_tcp_retransmissions
from specific_visualisations.tcp_window_size import plot_tcp_window_size
from specific_visualisations.tcp_seq_ack import plot_tcp_seq_ack
from specific_visualisations.udp_flows import plot_udp_flows
from specific_visualisations.udp_size import plot_udp_size
from specific_visualisations.http_methods import plot_http_methods
from specific_visualisations.http_codes import plot_http_codes
from specific_visualisations.arp_freq import plot_arp_freq
from specific_visualisations.arp_count import plot_arp_count
from specific_visualisations.icmp_types import plot_icmp_types
from specific_visualisations.icmp_freq import plot_icmp_freq
from specific_visualisations.dns_time import plot_dns_time
from specific_visualisations.dns_domains import plot_dns_domains
from specific_visualisations.modbus_codes import plot_modbus_codes
from specific_visualisations.modbus_exceptions import plot_modbus_exceptions
from specific_visualisations.dnp3_objects import plot_dnp3_objects
from specific_visualisations.dnp3_events import plot_dnp3_events
from specific_visualisations.s7_racks import plot_s7_racks
from specific_visualisations.s7_functions import plot_s7_functions

protocol_visualizations = {
    "TCP": [
        "Distribúcia TCP vlajok (Stĺpcový graf)",
        "Opakované TCP prenosy (Bodový graf)",
        "Veľkosť TCP okna v čase (Čiarový graf)",
        "Progresia SEQ/ACK vlajok (Scatter plot)"
    ],
    "UDP": [
        "Najväčšie UDP toky (Sankey diagram)",
        "Distribúcia veľkostí UDP paketov (Histogram)"
    ],
    "ICMP": [
        "Rozdelenie ICMP Type správ (Koláčový graf)",
        "Frekvencia ICMP požiadaviek a odpovedí (Stĺpcový graf)"
    ],
    "DNS": [
        "Distribúcia času DNS odoziev (Histogram)",
        "Top vyhľadávané doménové mená (Stĺpcový graf)"
    ],
    "HTTP": [
        "Frekvencia HTTP metód (Stĺpcový graf)",
        "Distribúcia HTTP kódov (Stĺpcový graf)"
    ],
    "ARP": [
        "Frekvencia ARP požiadaviek a odpovedí (Stĺpcový graf)",
        "Počet ARP správ podľa IP adresy (Stĺpcový graf)"
    ],
    "Modbus": [
        "Distribúcia Modbus kódov (Stĺpcový graf)",
        "Frekvencia Modbus výnimok (Stĺpcový graf)"
    ],
    "DNP3": [
        "Používané typy DNP3 objektov (Stĺpcový graf)",
        "DNP3 udalosti podľa tried (Stĺpcový graf)"
    ],
    "S7": [
        "Používané S7 funkcie – read/write (Stĺpcový graf)",
        "Používanie S7 rackov a slotov (Heatmapa)"
    ]
}

protocol_vis_function_map = {
    "Distribúcia TCP vlajok (Stĺpcový graf)": plot_tcp_flags,
    "Opakované TCP prenosy (Bodový graf)": plot_tcp_retransmissions,
    "Veľkosť TCP okna v čase (Čiarový graf)": plot_tcp_window_size,
    "Progresia SEQ/ACK vlajok (Scatter plot)": plot_tcp_seq_ack,
    "Najväčšie UDP toky (Sankey diagram)": plot_udp_flows,
    "Distribúcia veľkostí UDP paketov (Histogram)": plot_udp_size,
    "Frekvencia HTTP metód (Stĺpcový graf)": plot_http_methods,
    "Distribúcia HTTP kódov (Stĺpcový graf)": plot_http_codes,
    "Frekvencia ARP požiadaviek a odpovedí (Stĺpcový graf)": plot_arp_freq,
    "Počet ARP správ podľa IP adresy (Stĺpcový graf)": plot_arp_count,
    "Rozdelenie ICMP Type správ (Koláčový graf)": plot_icmp_types,
    "Frekvencia ICMP požiadaviek a odpovedí (Stĺpcový graf)": plot_icmp_freq,
    "Distribúcia času DNS odoziev (Histogram)": plot_dns_time,
    "Top vyhľadávané doménové mená (Stĺpcový graf)": plot_dns_domains,
    "Distribúcia Modbus kódov (Stĺpcový graf)": plot_modbus_codes,
    "Frekvencia Modbus výnimok (Stĺpcový graf)": plot_modbus_exceptions,
    "Používané typy DNP3 objektov (Stĺpcový graf)": plot_dnp3_objects,
    "DNP3 udalosti podľa tried (Stĺpcový graf)": plot_dnp3_events,
    "Používané S7 funkcie – read/write (Stĺpcový graf)": plot_s7_functions,
    "Používanie S7 rackov a slotov (Heatmapa)": plot_s7_racks,
}

def protocol_visualization_menu(stdscr, protocol, visualizations, json_file):
    current_selection = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, f"Vizualizácie pre protokol {protocol}:", curses.A_BOLD)
        stdscr.addstr(1, 0, "0. <- Späť")  # Back option

        for i, vis in enumerate(visualizations, start=1):
            if i == current_selection:
                stdscr.addstr(i + 1, 0, f"> {i}. {vis}", curses.A_REVERSE)
            else:
                stdscr.addstr(i + 1, 0, f"  {i}. {vis}")

        stdscr.addstr(len(visualizations) + 3, 0,
                      "Použite šípky na výber, ENTER pre potvrdenie, 'q' pre ukončenie.")
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP and current_selection > 0:
            current_selection -= 1
        elif key == curses.KEY_DOWN and current_selection < len(visualizations):
            current_selection += 1
        elif key == ord('\n'):
            if current_selection == 0:  # Back
                return None
            else:
                selected_vis = visualizations[current_selection - 1]
                func = protocol_vis_function_map.get(selected_vis)
                if func:
                    stdscr.clear()
                    stdscr.addstr(0, 0, f"Spúšťa sa vizualizácia: {selected_vis}...")
                    stdscr.refresh()
                    # Load JSON data
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                    func(data)
                    stdscr.addstr(2, 0, "Stlačte ľubovoľnú klávesu pre návrat do menu...")
                    stdscr.refresh()
                    stdscr.getch()
                else:
                    stdscr.addstr(len(visualizations) + 5, 0, "Vizualizácia nie je implementovaná.")
                    stdscr.refresh()
                    stdscr.getch()
                return None
        elif key == ord('q'):
            return "q"


def protocol_menu(stdscr, protocols):
    current_selection = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Vyberte protokol:", curses.A_BOLD)
        stdscr.addstr(1, 0, "0. <- Späť")  # Back option

        for i, protocol in enumerate(protocols, start=1):
            if i == current_selection:
                stdscr.addstr(i + 1, 0, f"> {i}. {protocol}", curses.A_REVERSE)
            else:
                stdscr.addstr(i + 1, 0, f"  {i}. {protocol}")

        stdscr.addstr(len(protocols) + 3, 0,
                      "Použite šípky na výber, ENTER pre potvrdenie, 'q' pre ukončenie.")
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP and current_selection > 0:
            current_selection -= 1
        elif key == curses.KEY_DOWN and current_selection < len(protocols):
            current_selection += 1
        elif key == ord('\n'):
            if current_selection == 0:  # Back
                return None
            else:
                return protocols[current_selection - 1]
        elif key == ord('q'):
            return "q"


def select_visualization(stdscr, json_file):
    visualizations = [
        "Objem dát v čase",
        "Distribúcia protokolov",
        "Top odosielatelia a prijímatelia",
        "Prepojenie aktívnych zariadení",
        "Distribúcia veľkosti paketov",
        "Analýza tokov",
        "Distribúcia portov",
        "Počet paketov v čase",
        "Výber špeciálnych vizualizácií na základe protokolu"
    ]

    protocols = [
        "TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP", "Modbus", "DNP3", "S7"
    ]

    protocol_visualizations = {
        "TCP": [
            "Distribúcia TCP vlajok (Stĺpcový graf)",
            "Opakované TCP prenosy (Bodový graf)",
            "Veľkosť TCP okna v čase (Čiarový graf)",
            "Progresia SEQ/ACK vlajok (Scatter plot)"
        ],
        "UDP": [
            "Najväčšie UDP toky (Sankey diagram)",
            "Distribúcia veľkostí UDP paketov (Histogram)"
        ],
        "ICMP": [
            "Rozdelenie ICMP Type správ (Koláčový graf)",
            "Frekvencia ICMP požiadaviek a odpovedí (Stĺpcový graf)"
        ],
        "DNS": [
            "Distribúcia času DNS odoziev (Histogram)",
            "Top vyhľadávané doménové mená (Stĺpcový graf)"
        ],
        "HTTP": [
            "Frekvencia HTTP metód (Stĺpcový graf)",
            "Distribúcia HTTP kódov (Stĺpcový graf)"
        ],
        "ARP": [
            "Frekvencia ARP požiadaviek a odpovedí (Stĺpcový graf)",
            "Počet ARP správ podľa IP adresy (Stĺpcový graf)"
        ],
        "Modbus": [
            "Distribúcia Modbus kódov (Stĺpcový graf)",
            "Frekvencia Modbus výnimok (Stĺpcový graf)"
        ],
        "DNP3": [
            "Používané typy DNP3 objektov (Stĺpcový graf)",
            "DNP3 udalosti podľa tried (Stĺpcový graf)"
        ],
        "S7": [
            "Používané S7 funkcie – read/write (Stĺpcový graf)",
            "Používanie S7 rackov a slotov (Heatmapa)"
        ]
    }

    current_selection = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Vyberte vizualizáciu:", curses.A_BOLD)

        for i, vis in enumerate(visualizations, start=1):
            if i - 1 == current_selection:
                stdscr.addstr(i, 0, f"> {i}. {vis}", curses.A_REVERSE)
            else:
                stdscr.addstr(i, 0, f"  {i}. {vis}")

        stdscr.addstr(len(visualizations) + 2, 0,
                      "Použite šípky na výber, ENTER pre potvrdenie, 'q' pre ukončenie.")
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP and current_selection > 0:
            current_selection -= 1
        elif key == curses.KEY_DOWN and current_selection < len(visualizations) - 1:
            current_selection += 1
        elif key == ord('\n'):
            selected_vis = visualizations[current_selection]
            if selected_vis == "Výber špeciálnych vizualizácií na základe protokolu":
                # Protocol submenu
                protocol = protocol_menu(stdscr, protocols)
                if protocol == "q" or protocol is None:
                    continue  # back or quit
                visualizations_for_protocol = protocol_visualizations.get(protocol, [])
                if not visualizations_for_protocol:
                    stdscr.addstr(len(visualizations) + 4, 0, f"Nenašli sa vizualizácie pre protokol {protocol}")
                    stdscr.refresh()
                    stdscr.getch()
                    continue
                result = protocol_visualization_menu(stdscr, protocol, visualizations_for_protocol, json_file)
                if result == "q":
                    return "q"
            else:
                stdscr.clear()
                stdscr.addstr(0, 0, f"Spúšťa sa vizualizácia: {selected_vis}...")
                stdscr.refresh()
                # Call the standard visualizations based on selection
                if selected_vis == "Objem dát v čase":
                    plot_data_usage(json_file)
                elif selected_vis == "Distribúcia protokolov":
                    plot_protocols(json_file)
                elif selected_vis == "Top odosielatelia a prijímatelia":
                    plot_top_senders_receivers(json_file)
                elif selected_vis == "Prepojenie aktívnych zariadení":
                    plot_network_topology(json_file)
                elif selected_vis == "Distribúcia veľkosti paketov":
                    plot_packet_size_distribution(json_file)
                elif selected_vis == "Analýza tokov":
                    plot_flow_analysis(json_file)
                elif selected_vis == "Distribúcia portov":
                    # Assuming you have this implemented somewhere
                    pass
                elif selected_vis == "Počet paketov v čase":
                    # Assuming you have this implemented somewhere
                    pass
                else:
                    stdscr.addstr(2, 0, "Táto vizualizácia zatiaľ nie je implementovaná.")
                    stdscr.refresh()
                    stdscr.getch()
                    continue
                stdscr.addstr(2, 0, "Stlačte ľubovoľnú klávesu pre návrat do menu...")
                stdscr.refresh()
                stdscr.getch()
        elif key == ord('q'):
            return "q"


def main(stdscr):
    parser = argparse.ArgumentParser(description="Live Visualizations for Network Data")
    parser.add_argument("json_file", help="Path to JSON file with packet data")
    args = parser.parse_args()

    json_file = args.json_file
    if not os.path.isfile(json_file):
        print(f"Súbor {json_file} neexistuje.")
        return

    curses.curs_set(0)  # Hide cursor
    result = select_visualization(stdscr, json_file)
    if result == "q":
        return


if __name__ == "__main__":
    curses.wrapper(main)
