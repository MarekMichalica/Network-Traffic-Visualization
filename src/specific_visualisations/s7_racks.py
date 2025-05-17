import json
import re
import numpy as np
import matplotlib.pyplot as plt


def plot_s7_racks(data_input):
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
        print("Neplatný vstup pre S7 udalosti")
        return

    if not packets:
        print("Žiadne pakety na spracovanie")
        return

    # Parse rack and slot counts from packets
    rack_slot_counts = {}

    for packet in packets:
        if packet.get('protocol', '').upper() == 'S7COMM' and 'payload' in packet:
            payload = packet['payload']
            rack_match = re.search(r'rack\s*=\s*(\d+)', payload, re.IGNORECASE)
            slot_match = re.search(r'slot\s*=\s*(\d+)', payload, re.IGNORECASE)
            if rack_match and slot_match:
                rack = int(rack_match.group(1))
                slot = int(slot_match.group(1))
                key = (rack, slot)
                rack_slot_counts[key] = rack_slot_counts.get(key, 0) + 1

    if not rack_slot_counts:
        print("Neboli nájdené žiadne platné rack/slot kombinácie v pakete")
        return

    # Extract unique racks and slots sorted
    racks = sorted({k[0] for k in rack_slot_counts.keys()})
    slots = sorted({k[1] for k in rack_slot_counts.keys()})

    # Build heatmap matrix (racks x slots)
    heatmap = np.zeros((len(racks), len(slots)), dtype=int)
    rack_index = {r: i for i, r in enumerate(racks)}
    slot_index = {s: i for i, s in enumerate(slots)}

    for (rack, slot), count in rack_slot_counts.items():
        i = rack_index[rack]
        j = slot_index[slot]
        heatmap[i, j] = count

    # Plotting
    fig, ax = plt.subplots(figsize=(max(6, len(slots)), max(4, len(racks))))

    cmap = plt.cm.Blues
    max_count = heatmap.max() if heatmap.max() > 0 else 1
    cax = ax.imshow(heatmap, cmap=cmap, interpolation='nearest', vmin=0, vmax=max_count)

    # Add count text annotations
    for i in range(len(racks)):
        for j in range(len(slots)):
            count = heatmap[i, j]
            if count > 0:
                color = 'white' if count > max_count / 2 else 'black'
                ax.text(j, i, str(count), ha='center', va='center', color=color, fontsize=10)

    ax.set_xticks(range(len(slots)))
    ax.set_xticklabels([f'S{s}' for s in slots])
    ax.set_yticks(range(len(racks)))
    ax.set_yticklabels([f'R{r}' for r in racks])

    ax.set_xlabel('Sloty')
    ax.set_ylabel('Racky')
    ax.set_title('Používanie S7 rackov a slotov', fontsize=16, fontweight='bold')

    cbar = fig.colorbar(cax, ax=ax)
    cbar.set_label('Počet')

    plt.tight_layout()
    plt.show()
