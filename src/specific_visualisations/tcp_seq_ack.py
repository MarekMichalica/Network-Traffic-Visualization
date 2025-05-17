import re
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
import json

def plot_tcp_seq_ack(data_input, pcap_file=None):
    # Extract packets (reuse your method for JSON/list/dict input)
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
        print("Žiadne pakety na zobrazenie")
        return

    seq_data = []
    ack_data = []

    # Extract sequence and ACK numbers
    for index, packet in enumerate(packets):
        if packet.get("protocol", "").upper() == "TCP":
            payload = packet.get("payload", "")
            seq_num = None
            ack_num = None

            if payload:
                seq_match = re.search(r"seq=(\d+)", payload)
                if seq_match:
                    seq_num = int(seq_match.group(1))

                ack_match = re.search(r"ack=(\d+)", payload)
                if ack_match:
                    ack_num = int(ack_match.group(1))

            time_val = packet.get("timestamp", f"Paket {index + 1}")
            # Parse timestamp if string
            if isinstance(time_val, str):
                try:
                    time_val_dt = datetime.fromisoformat(time_val)
                    time_val = time_val_dt
                except Exception:
                    # keep as string fallback
                    pass

            if seq_num is not None:
                seq_data.append({"time": time_val, "value": seq_num, "packetIndex": index})

            if ack_num is not None:
                ack_data.append({"time": time_val, "value": ack_num, "packetIndex": index})

    all_data = seq_data + ack_data
    if len(all_data) == 0:
        print("Žiadne TCP SEQ alebo ACK pakety")
        return

    # Prepare x-axis values: if datetime objects exist, sort and use them; else use indices or string labels
    # Extract unique sorted times
    unique_times = list({d['time'] for d in all_data})
    try:
        # Sort datetimes if possible
        unique_times.sort()
    except Exception:
        # If mixed types, fallback to original order
        pass

    # Map time values to numeric x-axis positions
    time_to_x = {t: i for i, t in enumerate(unique_times)}

    fig, ax = plt.subplots(figsize=(14, 7))

    # Plot sequence data (blue circles)
    seq_x = [time_to_x[d['time']] for d in seq_data]
    seq_y = [d['value'] for d in seq_data]
    ax.scatter(seq_x, seq_y, color="#4285F4", label='SEQ', alpha=0.8, s=50, marker='o')

    # Plot ACK data (red triangles)
    ack_x = [time_to_x[d['time']] for d in ack_data]
    ack_y = [d['value'] for d in ack_data]
    ax.scatter(ack_x, ack_y, color="#DB4437", label='ACK', alpha=0.8, s=50, marker='^')

    # Axis labels and title
    ax.set_title("Progresia SEQ a ACK vlajok", fontsize=16, fontweight='bold')
    ax.set_xlabel("Pakety v čase", fontsize=12)
    ax.set_ylabel("Číselná hodnota", fontsize=12)

    # Set x ticks and labels
    if all(isinstance(t, datetime) for t in unique_times):
        # Format datetime labels nicely
        ax.set_xticks(range(len(unique_times)))
        ax.set_xticklabels([t.strftime("%Y-%m-%d %H:%M:%S") for t in unique_times], rotation=45, ha='right')
    else:
        # Use string or index labels
        ax.set_xticks(range(len(unique_times)))
        ax.set_xticklabels([str(t) for t in unique_times], rotation=45, ha='right')

    # Add grid for readability
    ax.grid(True, linestyle='--', alpha=0.5)

    # Add legend (custom colored markers)
    seq_patch = mpatches.Patch(color="#4285F4", label='SEQ')
    ack_patch = mpatches.Patch(color="#DB4437", label='ACK')
    ax.legend(handles=[seq_patch, ack_patch])

    plt.tight_layout()
    plt.show()
