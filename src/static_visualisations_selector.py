import argparse
import curses
import pcap_analyzer

from static_visualisations.static_protocol_distribution import plot_protocols
from static_visualisations.static_data_usage import plot_data_usage
from static_visualisations.static_top_senders_receivers import plot_top_senders_receivers
from static_visualisations.static_network_topology import plot_network_topology
from static_visualisations.static_packet_size_distribution import plot_packet_size_distribution
from static_visualisations.static_flow_analysis import analyze_flows
from static_visualisations.static_traffic_heatmap import plot_traffic_heatmap
from static_visualisations.static_port_distribution import plot_port_distribution

# Import protocol-specific visualizations
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
    ],
}

# Map visualization description to function
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


def protocol_visualization_menu(stdscr, protocol, visualizations):
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
                return visualizations[current_selection - 1]
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


def select_visualization(stdscr):
    visualizations = [
        "Objem dát v čase",
        "Distribúcia protokolov",
        "Top odosielatelia a prijímatelia",
        "Prepojenie aktívnych zariadení",
        "Distribúcia veľkosti paketov",
        "Analýza tokov",
        "Distribúcia portov",
        "Tepelná mapa prevádzky v dňoch",
        "Výber špeciálnych vizualizácií na základe protokolu"
    ]

    protocols = [
        "TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP", "Modbus", "DNP3", "S7"
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
        elif key == ord('\n'):
            if current_selection == 8:  # Protocol-specific submenu
                while True:
                    protocol = protocol_menu(stdscr, protocols)
                    if protocol == "q":
                        return "q"
                    if protocol is None:
                        break  # Back to main menu

                    selected_vis = protocol_visualization_menu(stdscr, protocol, protocol_visualizations[protocol])
                    if selected_vis == "q":
                        return "q"
                    if selected_vis is None:
                        continue  # Back to protocol menu

                    stdscr.clear()
                    stdscr.addstr(0, 0, f"Vybrali ste: {selected_vis}. Vizualizácia sa spustí...")
                    stdscr.refresh()

                    return ("protocol", selected_vis)
            else:
                return ("static", str(current_selection + 1))
        elif key == ord('q'):
            return "q"

def main(stdscr, pcap_file):
    curses.curs_set(0)
    stdscr.keypad(True)

    while True:
        filters = {}
        analysis_result = pcap_analyzer.analyze_packets(pcap_file, filters)
        filtered_packets = analysis_result.get("filtered_packets", [])

        selection = select_visualization(stdscr)
        if selection == "q":
            break

        if isinstance(selection, tuple):
            mode, choice = selection

            if mode == "static":
                if choice == "1":
                    plot_data_usage(filtered_packets, pcap_file)
                elif choice == "2":
                    protocol_counts = analysis_result.get("protocol_counts", {})
                    plot_protocols(protocol_counts, pcap_file)
                elif choice == "3":
                    plot_top_senders_receivers(filtered_packets, pcap_file)
                elif choice == "4":
                    plot_network_topology(filtered_packets, pcap_file)
                elif choice == "5":
                    plot_packet_size_distribution(filtered_packets, pcap_file)
                elif choice == "6":
                    analyze_flows(filtered_packets, pcap_file)
                elif choice == "7":
                    plot_port_distribution(filtered_packets, pcap_file)
                elif choice == "8":
                    plot_traffic_heatmap(filtered_packets, pcap_file)

            elif mode == "protocol":
                func = protocol_vis_function_map.get(choice)
                if func:
                    func(filtered_packets)

        stdscr.clear()
        stdscr.addstr(0, 0, "Stlačte ľubovoľnú klávesu pre návrat do hlavného menu...")
        stdscr.refresh()
        stdscr.getch()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP Visualizer")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    args = parser.parse_args()

    curses.wrapper(main, args.pcap_file)
