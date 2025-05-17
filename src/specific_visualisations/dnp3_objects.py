import json
import re
import matplotlib.pyplot as plt


def plot_dnp3_objects(data_input):
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
        print("Neplatný vstup pre DNP3 objekty")
        return

    if not packets:
        print("Žiadne pakety na zobrazenie")
        return

    # Extract object counts from DNP3 packets
    object_counts = {}
    object_pattern = re.compile(r'Object: (\d+)')

    for packet in packets:
        if packet.get('protocol', '').upper() == 'DNP3':
            payload = packet.get('payload', '')
            if 'Object:' in payload:
                match = object_pattern.search(payload)
                if match:
                    object_type = match.group(1)
                    object_counts[object_type] = object_counts.get(object_type, 0) + 1

    if not object_counts:
        print("Žiadne dostupné DNP3 objekty")
        return

    # Object code descriptions
    object_descriptions = {
        '1': 'Binárny vstup',
        '2': 'Binárny výstup',
        '10': 'Binárny komandný výstup',
        '20': 'Počítadlo',
        '21': 'Zmrazené počítadlo',
        '30': 'Analógový vstup',
        '31': 'Zmrazený analógový vstup',
        '40': 'Analógový výstup',
        '50': 'Časová synchronizácia',
        '60': 'Trieda dát',
        '70': 'Interný diagnostický objekt',
        '80': 'Objekt aktivačných aplikácií',
        '90': 'Objekt súborov',
        '100': 'Objekt záznamu udalostí',
        '110': 'Objekt virtuálneho terminálu',
        '120': 'Objekt riadenia pomeru prenosu'
    }

    # Prepare data for plotting, sorted descending by count
    chart_data = sorted(
        [
            {
                'object_type': ot,
                'description': object_descriptions.get(ot, f'Objekt {ot}'),
                'count': count
            }
            for ot, count in object_counts.items()
        ],
        key=lambda x: x['count'],
        reverse=True
    )

    object_types = [d['object_type'] for d in chart_data]
    counts = [d['count'] for d in chart_data]
    labels = [f"{d['object_type']} ({d['description']})" for d in chart_data]

    # Plotting bar chart
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(object_types, counts, color='#4285F4', width=0.6)

    # Add value labels above bars
    for bar, count in zip(bars, counts):
        height = bar.get_height()
        ax.annotate(
            f'{count}',
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 5),  # offset above the bar
            textcoords="offset points",
            ha='center', va='bottom',
            fontsize=10
        )

    # Rotate x-axis labels for readability
    ax.set_xticks(object_types)
    ax.set_xticklabels(object_types, rotation=45, ha='right')

    # Titles and labels
    ax.set_title('Používané typy DNP3 objektov', fontsize=14, fontweight='bold')
    ax.set_xlabel('Typ objektu')
    ax.set_ylabel('Počet výskytov')

    plt.tight_layout()
    plt.show()
