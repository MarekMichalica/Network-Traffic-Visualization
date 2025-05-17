import json
import re
import matplotlib.pyplot as plt

def plot_icmp_freq(data_input):
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
        print("Neplatný vstup pre ICMP frekvenciu")
        return

    if not packets:
        print("Žiadne pakety na zobrazenie")
        return

    # Filter ICMP packets and count requests and responses
    icmp_packets = {
        'Požiadavky': 0,
        'Odpovede': 0
    }

    for pkt in packets:
        if pkt.get('protocol', '').upper() == 'ICMP':
            payload = pkt.get('payload', '')
            if 'Type: 8' in payload:
                icmp_packets['Požiadavky'] += 1
            elif 'Type: 0' in payload:
                icmp_packets['Odpovede'] += 1

    if icmp_packets['Požiadavky'] == 0 and icmp_packets['Odpovede'] == 0:
        print("Žiadne dostupné ICMP pakety")
        return

    categories = list(icmp_packets.keys())
    counts = list(icmp_packets.values())

    # Plot bar chart
    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(categories, counts, color=['#4285F4', '#34A853'])

    # Add count labels on top of bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 5),  # 5 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

    ax.set_title('Frekvencia ICMP požiadaviek a odpovedí', fontsize=14, fontweight='bold')
    ax.set_ylabel('Počet paketov')

    plt.tight_layout()
    plt.show()
