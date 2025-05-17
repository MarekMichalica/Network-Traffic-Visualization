import json
import re
import matplotlib.pyplot as plt

def plot_icmp_types(data_input):
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
        print("Neplatný vstup pre ICMP vizualizáciu")
        return

    if not packets:
        print("Žiadne pakety na zobrazenie")
        return

    # ICMP type code -> human-readable name mapping
    icmp_type_names = {
        "0": "Echo Reply",
        "3": "Destination Unreachable",
        "8": "Echo Request",
        "11": "Time Exceeded",
        "12": "Parameter Problem",
        "13": "Timestamp",
        "14": "Timestamp Reply"
    }

    # Count ICMP types
    icmp_types = {}

    for pkt in packets:
        if pkt.get('protocol', '').upper() == 'ICMP':
            payload = pkt.get('payload', '')
            match = re.search(r'Type: (\d+)', payload)
            if match:
                type_code = match.group(1)
                type_name = icmp_type_names.get(type_code, f"Type {type_code}")
                icmp_types[type_name] = icmp_types.get(type_name, 0) + 1

    if not icmp_types:
        print("Žiadne dostupné ICMP správy")
        return

    # Prepare data for pie chart
    labels = []
    counts = []
    for k, v in sorted(icmp_types.items(), key=lambda item: item[1], reverse=True):
        labels.append(f"{k} ({v})")
        counts.append(v)

    # Plot pie chart
    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts = ax.pie(counts, labels=None, startangle=90, autopct=None, colors=plt.cm.tab10.colors)

    # Draw legend with counts
    ax.legend(wedges, labels, title="ICMP Typy", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))

    ax.set_title('Rozdelenie ICMP Type správ', fontsize=14, fontweight='bold')

    plt.tight_layout()
    plt.show()
