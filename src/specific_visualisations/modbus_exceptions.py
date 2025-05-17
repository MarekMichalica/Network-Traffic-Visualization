import json
import re
import matplotlib.pyplot as plt

def plot_modbus_exceptions(data_input):
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
        print("Neplatný vstup pre Modbus výnimky")
        return

    if not packets:
        print("Žiadne pakety na zobrazenie")
        return

    # Extract exception counts
    exception_counts = {}
    exception_pattern = re.compile(r'Exception: (\d+)')

    for packet in packets:
        if packet.get('protocol', '').upper() == 'MODBUS':
            payload = packet.get('payload', '')
            if 'Exception:' in payload:
                match = exception_pattern.search(payload)
                if match:
                    code = match.group(1)
                    exception_counts[code] = exception_counts.get(code, 0) + 1

    if not exception_counts:
        print("Žiadne dostupné Modbus výnimky")
        return

    # Exception code descriptions
    exception_descriptions = {
        '1': 'Neplatná funkcia',
        '2': 'Neplatná adresa',
        '3': 'Neplatná hodnota',
        '4': 'Zlyhanie zariadenia',
        '5': 'Potvrdenie',
        '6': 'Zariadenie zaneprázdnené',
        '7': 'Chyba parity',
        '8': 'Chyba memory parity',
        '10': 'Brána nedostupná',
        '11': 'Zariadenie neodpovedá'
    }

    # Prepare data for plotting, sorted by count descending
    chart_data = sorted(
        [
            {
                'code': code,
                'description': exception_descriptions.get(code, f'Výnimka {code}'),
                'count': count
            }
            for code, count in exception_counts.items()
        ],
        key=lambda x: x['count'],
        reverse=True
    )

    labels = [f"{d['code']}: {d['description']}" for d in chart_data]
    counts = [d['count'] for d in chart_data]

    # Donut chart plot
    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        counts,
        labels=None,  # We'll handle legend manually
        autopct=lambda pct: f'{int(round(pct))}%' if pct >= 5 else '',
        startangle=90,
        pctdistance=0.75,
        wedgeprops=dict(width=0.4, edgecolor='w')
    )

    # Set legend outside plot
    ax.legend(
        wedges,
        labels,
        title="Modbus výnimky",
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1),
        fontsize=10
    )

    ax.set_title('Frekvencia Modbus výnimok', fontsize=14, fontweight='bold')

    plt.tight_layout()
    plt.show()
