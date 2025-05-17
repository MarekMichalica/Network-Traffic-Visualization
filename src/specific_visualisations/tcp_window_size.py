import re
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
import json

def plot_tcp_window_size(data_input, pcap_file=None):
    # Extract packets (assuming you have extract_packets implemented or use your pattern)
    packets = None
    if isinstance(data_input, str):
        try:
            with open(data_input, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    packets = loaded
                elif isinstance(loaded, dict):
                    if "packets" in loaded:
                        packets = loaded["packets"]
                    else:
                        print("Neplatný formát JSON: očakávaný kľúč 'packets'")
                        return
                else:
                    print("Neplatný formát JSON: očakávaný zoznam alebo slovník")
                    return
        except Exception as e:
            print(f"Chyba pri načítaní JSON: {e}")
            return
    elif isinstance(data_input, dict):
        if "packets" in data_input:
            packets = data_input["packets"]
        else:
            packets = [data_input]
    elif isinstance(data_input, list):
        packets = data_input
    else:
        print("Neplatný vstup pre TCP vizualizáciu")
        return

    if not packets:
        print("Neboli nájdené žiadne pakety na zobrazenie")
        return

    # Extract window size data
    times = []
    window_sizes = []

    for index, packet in enumerate(packets):
        if packet.get("protocol", "").upper() == "TCP":
            payload = packet.get("payload", "")
            if payload:
                # Extract window size from payload using regex
                match = re.search(r"win=(\d+)", payload)
                if match:
                    window_size = int(match.group(1))
                    timestamp = packet.get("timestamp")
                    # Parse timestamp if it's a string
                    if isinstance(timestamp, str):
                        try:
                            # Try parsing common datetime format (adjust if needed)
                            timestamp_dt = datetime.fromisoformat(timestamp)
                        except Exception:
                            timestamp_dt = None
                    else:
                        timestamp_dt = None

                    # Use timestamp datetime or fallback to packet index for x-axis
                    times.append(timestamp_dt if timestamp_dt else index)
                    window_sizes.append(window_size)

    if not window_sizes:
        print("Neboli nájdené žiadne veľkosti TCP okna")
        return

    # Plotting
    fig, ax = plt.subplots(figsize=(12, 6))

    if all(isinstance(t, datetime) for t in times):
        # Times are datetime objects — plot with date formatter
        ax.plot(times, window_sizes, marker='o', linestyle='-', color='steelblue')
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
        fig.autofmt_xdate(rotation=45)
        ax.set_xlabel("Čas")
    else:
        # Times are indices or mixed — plot with indices on x-axis
        ax.plot(times, window_sizes, marker='o', linestyle='-', color='steelblue')
        ax.set_xlabel("Paket index")

    ax.set_ylabel("Veľkosť okna")
    ax.set_title("Veľkosť TCP okna v čase")
    ax.grid(True)

    plt.tight_layout()
    plt.show()
