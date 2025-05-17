import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
import re

def plot_tcp_retransmissions(data_input, pcap_file=None):
    packets = None

    # Load or parse packets based on input type
    if isinstance(data_input, str):
        # Assume JSON filename
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

    # Process packets for retransmissions
    retransmission_data = []
    time_counter = 0
    time_step = 1

    for index, packet in enumerate(packets):
        protocol = packet.get("protocol", "").upper()
        if protocol == "TCP":
            timestamp = packet.get("timestamp")
            # Parse timestamp if exists
            time_val = None
            if timestamp:
                try:
                    time_val = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    try:
                        # try float timestamp fallback
                        time_val = datetime.fromtimestamp(float(timestamp))
                    except Exception:
                        time_val = datetime.fromtimestamp(time_counter)
                        time_counter += time_step
            else:
                time_val = datetime.fromtimestamp(time_counter)
                time_counter += time_step

            payload = packet.get("payload", "")
            is_retransmission = bool(re.search(r"[Rr]etransmission", str(payload)))

            retransmission_data.append({
                "time": time_val,
                "is_retransmission": 1 if is_retransmission else 0,
                "packet_index": index + 1
            })

    if not retransmission_data:
        print("Neboli nájdené žiadne opakované TCP prenosy")
        return

    # Plot
    times = [d["time"] for d in retransmission_data]
    flags = [d["is_retransmission"] for d in retransmission_data]
    colors = ['red' if flag == 1 else 'green' for flag in flags]

    plt.figure(figsize=(12, 6))
    plt.scatter(times, flags, c=colors, s=50)

    plt.title("Opakované TCP prenosy", fontsize=14, fontweight='bold')
    plt.xlabel("Čas")
    plt.ylabel("Opakovaný prenos")
    plt.yticks([0, 1], ["Nie", "Áno"])

    if isinstance(times[0], datetime):
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.gcf().autofmt_xdate()

    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()