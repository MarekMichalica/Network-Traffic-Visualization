import json
import matplotlib.pyplot as plt

def plot_arp_freq(data_input):
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
        print("Neplatný vstup pre ARP vizualizáciu")
        return

    if not packets:
        print("Žiadne pakety na zobrazenie")
        return

    # Count ARP message types
    arp_counts = {
        "ARP Request (who-has)": 0,
        "ARP Reply (is-at)": 0
    }

    for pkt in packets:
        if pkt.get('protocol', '').upper() == 'ARP':
            payload = pkt.get('payload', '')
            if "who-has" in payload:
                arp_counts["ARP Request (who-has)"] += 1
            elif "is-at" in payload:
                arp_counts["ARP Reply (is-at)"] += 1

    if all(count == 0 for count in arp_counts.values()):
        print("Žiadne dostupné ARP správy")
        return

    types = list(arp_counts.keys())
    counts = list(arp_counts.values())

    # Colors for ARP types
    color_map = {
        "ARP Request (who-has)": '#4285F4',
        "ARP Reply (is-at)": '#34A853'
    }
    colors = [color_map[t] for t in types]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(types, counts, color=colors)

    # Add counts above bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')

    ax.set_title('Frekvencia ARP požiadaviek a odpovedí', fontsize=14, fontweight='bold')
    ax.set_xlabel('Typ ARP správy')
    ax.set_ylabel('Počet správ')

    plt.xticks(rotation=-15, ha='right')
    plt.tight_layout()
    plt.show()
