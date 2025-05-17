import matplotlib.pyplot as plt
import json
import re

def extract_flags(packets):
    flags_count = {
        'SYN': 0,
        'ACK': 0,
        'FIN': 0,
        'RST': 0,
        'PSH': 0,
        'URG': 0
    }

    bracketed_pattern = re.compile(r'\[(.*?)\]')

    for packet in packets:
        protocol = packet.get('protocol', '').upper()
        if protocol not in ['TCP', 'TLS']:
            continue

        payload = packet.get('payload', '') or ''
        matches = bracketed_pattern.findall(payload)

        for group in matches:
            flags = [flag.strip().upper() for flag in group.split(',')]
            for flag in flags:
                if flag in flags_count:
                    flags_count[flag] += 1

    return flags_count

def plot_tcp_flags(data_input, pcap_file=None):
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

    flags = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']
    flags_count = extract_flags(packets)
    counts = [flags_count[f] for f in flags]

    if max(counts) == 0:
        print("Neboli nájdené žiadne TCP vlajky v dátach")
        plt.figure(figsize=(8, 4))
        plt.text(0.5, 0.5, "Žiadne dostupné TCP vlajky", ha='center', va='center', fontsize=14)
        plt.axis('off')
        plt.show()
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(flags, counts, color='steelblue')

    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 5),
                    textcoords='offset points',
                    ha='center', va='bottom', fontsize=10)

    ax.set_title('Distribúcia TCP vlajok' + (f"\n{pcap_file}" if pcap_file else ""), fontsize=14, fontweight='bold')
    ax.set_xlabel('TCP vlajky')
    ax.set_ylabel('Počet')

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.show()
