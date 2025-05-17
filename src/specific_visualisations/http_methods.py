import json
import re
import matplotlib.pyplot as plt

def plot_http_methods(data_input):
    # Handle input formats (file path JSON / dict / list)
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
        print("Neplatný vstup pre HTTP vizualizáciu")
        return

    if not packets:
        print("Žiadne pakety na zobrazenie")
        return

    # Extract HTTP method counts
    method_counts = {}
    method_pattern = re.compile(r'Method: ([A-Z]+)')

    for pkt in packets:
        if pkt.get('protocol', '').upper() == 'HTTP':
            payload = pkt.get('payload', '')
            match = method_pattern.search(payload)
            if match:
                method = match.group(1)
                method_counts[method] = method_counts.get(method, 0) + 1

    if not method_counts:
        print("Žiadne dostupné HTTP metódy")
        return

    # Sort methods by frequency descending
    sorted_methods = sorted(method_counts.items(), key=lambda x: x[1], reverse=True)
    methods, counts = zip(*sorted_methods)

    # Define colors for common HTTP methods, fallback to grey
    color_map = {
        'GET': '#4285F4',
        'POST': '#34A853',
        'PUT': '#FBBC05',
        'DELETE': '#EA4335',
        'HEAD': '#8F00FF',
        'OPTIONS': '#FF6D01',
        'PATCH': '#46BDC6'
    }
    colors = [color_map.get(m, '#999999') for m in methods]

    # Plot bar chart
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(methods, counts, color=colors)

    ax.set_title('Frekvencia HTTP metód', fontsize=14, fontweight='bold')
    ax.set_xlabel('HTTP Metóda')
    ax.set_ylabel('Počet požiadaviek')

    # Add count labels on top of bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')

    plt.tight_layout()
    plt.show()
